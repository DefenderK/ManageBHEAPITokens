#Requires -Version 5.1
<#
.SYNOPSIS
Reports stale BloodHound user API tokens; optionally revokes selected tokens.
.DESCRIPTION
Default opens an interactive menu. Revocation requires selection and typed confirmation.
Configuration precedence: explicit parameters, .env beside this script, process environment.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$BaseUrl,
    [ValidateRange(1,36500)][int]$Days = 90,
    [string]$TokenId,
    [string]$TokenKey,
    [string]$BearerToken,
    [string]$EnvFile,
    [switch]$NoEnvFile,
    [string[]]$UserId = @(),
    [string[]]$ExcludeUserId = @(),
    [string[]]$ExcludeTokenId = @(),
    [switch]$DryRun,
    [switch]$Revoke,
    [switch]$NonInteractive,
    [ValidateRange(1,1000)][int]$MaxRevocations = 20,
    [string]$OutputDirectory,
    [ValidateRange(1,1024)][int]$AuditMaxSizeMB = 10,
    [ValidateRange(0,10000)][int]$AuditArchiveCount = 0,
    [ValidateRange(1,300)][int]$TimeoutSec = 30
)

Set-StrictMode -Version Latest
$script:BHECleanupDirectory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

function Read-BHEEnvFile([string]$Path) {
    $values = @{}
    $allowed = @('BHE_URL','BHE_TOKEN_ID','BHE_TOKEN_KEY','BHE_BEARER_TOKEN')
    try { $lines = [IO.File]::ReadAllLines($Path) }
    catch { throw 'Unable to read configuration file. Check the path and permissions.' }
    for ($lineNumber = 0; $lineNumber -lt $lines.Count; $lineNumber++) {
        $line = $lines[$lineNumber].Trim()
        if (!$line -or $line.StartsWith('#')) { continue }
        $errorText = "Invalid .env configuration at line $($lineNumber + 1). Expected a supported KEY=value assignment; values are not shown."
        if ($line -cnotmatch '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { throw $errorText }
        $key = $Matches[1]; $value = $Matches[2].Trim()
        if ($key -cnotin $allowed -or $values.ContainsKey($key)) { throw $errorText }
        if ($value.StartsWith('"') -or $value.StartsWith("'")) {
            if ($value.Length -lt 2 -or $value[$value.Length - 1] -cne $value[0]) { throw $errorText }
            $value = $value.Substring(1, $value.Length - 2)
        }
        # Deliberately literal: no variable expansion, escape interpretation, or code execution.
        # Only whole-line comments are supported; '#' inside a value is preserved.
        $values[$key] = $value
    }
    return $values
}

function Resolve-BHEConfiguration($Explicit, [string]$EnvFile, [switch]$NoEnvFile) {
    if ($NoEnvFile -and $Explicit.ContainsKey('EnvFile')) { throw 'Choose EnvFile or NoEnvFile, not both.' }
    $fileValues = @{}
    $path = Join-Path $script:BHECleanupDirectory '.env'
    if (!$NoEnvFile) {
        if ($Explicit.ContainsKey('EnvFile')) {
            if ([string]::IsNullOrWhiteSpace($EnvFile)) { throw 'EnvFile must specify a file path.' }
            $path = $EnvFile
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) { $fileValues = Read-BHEEnvFile $path }
        elseif ($Explicit.ContainsKey('EnvFile') -or (Test-Path -LiteralPath $path)) {
            throw 'Configuration file does not exist or is not a readable file.'
        }
    }
    $resolved = @{}
    $mapping = @{ BaseUrl = 'BHE_URL'; TokenId = 'BHE_TOKEN_ID'; TokenKey = 'BHE_TOKEN_KEY'; BearerToken = 'BHE_BEARER_TOKEN' }
    foreach ($name in $mapping.Keys) {
        $key = $mapping[$name]
        if ($Explicit.ContainsKey($name)) { $resolved[$name] = [string]$Explicit[$name] }
        elseif ($fileValues.ContainsKey($key)) { $resolved[$name] = [string]$fileValues[$key] }
        else { $resolved[$name] = [Environment]::GetEnvironmentVariable($key, 'Process') }
    }
    return $resolved
}

function Get-BHEField($Object, [string]$Name) {
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function ConvertFrom-BHENullable($Value, [string]$Field) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ((Get-BHEField $Value 'Valid') -eq $true) { return Get-BHEField $Value $Field }
    return $null
}

function ConvertTo-BHEUuid($Value) {
    $parsed = [guid]::Empty
    if ([guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString()
    }
    return $null
}

function ConvertTo-BHEOrigin([string]$BaseUrl) {
    $uri = $null
    $message = 'BaseUrl must be an HTTPS origin or an HTTP loopback origin (127.0.0.1, [::1], localhost), without a path, credentials, query, or fragment.'
    if (![Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http','https') -or !$uri.Host -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') { throw $message }
    if ($uri.Scheme -eq 'http') {
        # Check literal addresses/names only. Never trust a hostname merely because DNS resolves locally.
        $hostName = $uri.DnsSafeHost.Trim('[',']')
        $address = $null
        $loopback = $hostName -eq 'localhost'
        if ([Net.IPAddress]::TryParse($hostName, [ref]$address)) { $loopback = [Net.IPAddress]::IsLoopback($address) }
        if (!$loopback) { throw $message }
    }
    return $uri
}

function ConvertTo-BHETime($Value) {
    # Require an explicit offset; never interpret tenant timestamps in local time.
    if ([string]$Value -notmatch '(Z|[+-]\d{2}:\d{2})$') { return $null }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $parsed.ToUniversalTime() }
    return $null
}

function Get-BHEHmac([byte[]]$Key, [byte[]]$Bytes) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try { $hmac.Key = $Key; return ,($hmac.ComputeHash($Bytes)) } finally { $hmac.Dispose() }
}

function Invoke-BHERequest($Context, [ValidateSet('GET','DELETE')][string]$Method, [string]$Path) {
    $headers = @{ Accept = 'application/json' }
    if ($Context.BearerToken) { $headers.Authorization = 'Bearer ' + $Context.BearerToken }
    else {
        $date = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $encoding = [Text.Encoding]::UTF8
        $operation = Get-BHEHmac $encoding.GetBytes($Context.TokenKey) $encoding.GetBytes($Method + $Path)
        $dateKey = Get-BHEHmac $operation $encoding.GetBytes($date.Substring(0,13))
        $signature = Get-BHEHmac $dateKey ([byte[]]@())
        $headers.Authorization = 'bhesignature ' + $Context.TokenId
        $headers.RequestDate = $date
        $headers.Signature = [Convert]::ToBase64String($signature)
    }
    try {
        # No redirects, TLS bypass, credential logging, or automatic mutation retries.
        $response = Invoke-WebRequest -Uri ($Context.BaseUrl + $Path) -Method $Method -Headers $headers `
            -UseBasicParsing -MaximumRedirection 0 -TimeoutSec $Context.TimeoutSec -ErrorAction Stop
    } catch {
        $status = 'transport failure'
        $errorResponse = Get-BHEField $_.Exception 'Response'
        if ($null -ne $errorResponse) { $status = 'HTTP ' + [int]$errorResponse.StatusCode }
        # Do not propagate server response bodies, which might contain sensitive data.
        throw "$Method request failed ($status). No automatic retry was made."
    }
    if ([int]$response.StatusCode -ne 200) { throw "Unexpected HTTP status for $Method; stopping." }
    if ($Method -eq 'GET') {
        try { return ($response.Content | ConvertFrom-Json -ErrorAction Stop) }
        catch { throw 'Invalid JSON response; stopping.' }
    }
}

function Get-BHETokens($Context, [string]$Id) {
    $path = '/api/v2/tokens'
    if ($Id) { $path += '?id=eq:' + [Uri]::EscapeDataString($Id) }
    $response = Invoke-BHERequest $Context GET $path
    $data = Get-BHEField $response 'data'
    if ($null -eq $data -or $null -eq $data.PSObject.Properties['tokens'] -or
        $null -eq $data.tokens -or $data.tokens -isnot [System.Array]) {
        throw 'Expected data.tokens array is missing; stopping.'
    }
    # Current endpoint returns an unpaginated collection. Do not invent skip/limit support.
    return $data.tokens
}

function Test-BHEDeletionMarker($Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return ![string]::IsNullOrWhiteSpace($Value) }
    # sql.NullTime is serialized as { Time: ..., Valid: false } when no timestamp exists.
    # Only an actual Boolean false establishes an absent nullable timestamp.
    $valid = Get-BHEField $Value 'Valid'
    if ($valid -is [bool] -and !$valid) { return $false }
    # Valid=true and unrecognized/malformed representations remain excluded.
    return $true
}

function Get-BHETokenAssessment($Token, $Policy) {
    $id = ConvertTo-BHEUuid (Get-BHEField $Token 'id')
    $owner = ConvertTo-BHEUuid (ConvertFrom-BHENullable (Get-BHEField $Token 'user_id') 'UUID')
    $last = ConvertTo-BHETime (Get-BHEField $Token 'last_access')
    $created = ConvertTo-BHETime (Get-BHEField $Token 'created_at')
    $reason = 'Eligible'
    if (!$id) { $reason = 'InvalidTokenId' }
    elseif (!$owner) { $reason = 'NoValidUserOwner' }
    elseif ($Policy.TokenId -and $id -eq $Policy.TokenId) { $reason = 'ExecutingToken' }
    elseif ($id -in $Policy.ExcludeTokenId) { $reason = 'ExcludedToken' }
    elseif ($owner -in $Policy.ExcludeUserId) { $reason = 'ExcludedUser' }
    elseif ($Policy.UserId.Count -gt 0 -and $owner -notin $Policy.UserId) { $reason = 'OutsideUserScope' }
    elseif (Test-BHEDeletionMarker (Get-BHEField $Token 'deleted_at')) { $reason = 'DeletedOrUnknownDeletionState' }
    elseif ($null -eq $last -or $last.Year -le 1) { $reason = 'UnknownOrNeverUsed' }
    elseif ($last -gt $Policy.Now) { $reason = 'FutureLastAccess' }
    # Initial last_access can be assigned just before the database sets created_at.
    # Permit up to one second of initialization skew; never replace the access-age cutoff.
    elseif ($null -eq $created -or $created.Year -le 1 -or $created -gt $Policy.Now -or
        ($created - $last).TotalMilliseconds -gt 1000) { $reason = 'InvalidCreationTime' }
    elseif ($last -ge $Policy.Cutoff) { $reason = 'Recent' }
    [pscustomobject][ordered]@{
        TokenId = $id; UserId = $owner
        Name = [string](ConvertFrom-BHENullable (Get-BHEField $Token 'name') 'String')
        CreatedAt = [string](Get-BHEField $Token 'created_at')
        LastAccess = [string](Get-BHEField $Token 'last_access')
        Reason = $reason
    }
}

function Write-BHEJsonFile([string]$Path, $Value) {
    # CreateNew prevents accidental overwrite. Failure to persist evidence stops the run.
    $json = ConvertTo-Json -InputObject $Value -Depth 8
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally { $stream.Dispose() }
}

function Open-BHEAuditLock([string]$Journal) {
    if (![IO.Directory]::Exists([IO.Path]::GetDirectoryName($Journal))) { throw 'Audit directory is missing.' }
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        try { return [IO.File]::Open($Journal + '.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] { [Threading.Thread]::Sleep(50) }
    }
    throw 'Audit log is busy; could not acquire the write/rotation lock within five seconds.'
}

function Get-BHEAuditArchives([string]$Journal) {
    $root = [IO.Path]::GetDirectoryName($Journal)
    Get-ChildItem -LiteralPath $root -File -Filter 'audit-*.jsonl' -ErrorAction Stop |
        Where-Object { $_.Name -match '^audit-\d{8}T\d{13}Z-[a-f0-9]{32}\.jsonl$' -and !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        Sort-Object Name -Descending
}

function Write-BHEAudit($Session, [string]$Action, $Details = @{}) {
    $entry = [ordered]@{
        AtUtc = [DateTimeOffset]::UtcNow.ToString('o'); Action = $Action
        SessionId = $Session.Id; BaseUrl = $Session.BaseUrl
        LocalOperator = $Session.Operator; SigningTokenId = $Session.SigningTokenId
        Details = $Details
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($entry | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine)
    $maxBytes = Get-BHEField $Session 'AuditMaxBytes'
    if ($null -eq $maxBytes) { $maxBytes = 10MB }
    $retain = Get-BHEField $Session 'AuditArchiveCount'
    if ($null -eq $retain) { $retain = 0 }
    $lock = Open-BHEAuditLock $Session.Journal
    try {
        if ([IO.File]::Exists($Session.Journal)) {
            $length = ([IO.FileInfo]$Session.Journal).Length
            if ($length -gt 0 -and $length + $bytes.Length -gt $maxBytes) {
                $stamp = [DateTimeOffset]::UtcNow
                $newest = Get-BHEAuditArchives $Session.Journal | Select-Object -First 1
                if ($null -ne $newest) {
                    $previous = [DateTimeOffset]::ParseExact($newest.Name.Split('-')[1], 'yyyyMMddTHHmmssfffffffZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
                    if ($stamp -le $previous) { $stamp = $previous.AddTicks(1) }
                }
                # Monotonic names preserve append order even if the clock stalls or moves backwards.
                $archive = 'audit-' + $stamp.ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [guid]::NewGuid().ToString('N') + '.jsonl'
                [IO.File]::Move($Session.Journal, (Join-Path ([IO.Path]::GetDirectoryName($Session.Journal)) $archive))
            }
        }
        # One complete UTF-8 entry per append. Local evidence is written even in WhatIf mode.
        $stream = [IO.File]::Open($Session.Journal, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ($Action -eq 'SessionStarted') {
            # Earlier immutable archives cannot contain this session; avoid scanning them in its viewer.
            $priorArchive = Get-BHEAuditArchives $Session.Journal | Select-Object -First 1
            $Session.AuditStartArchive = if ($null -ne $priorArchive) { $priorArchive.Name } else { '' }
        }
        if ($retain -gt 0) {
            $archives = @(Get-BHEAuditArchives $Session.Journal)
            foreach ($file in @($archives | Select-Object -Skip $retain)) {
                # Only generated archive files in this audit directory are eligible for retention cleanup.
                [IO.File]::Delete($file.FullName)
            }
        }
    } finally { $lock.Dispose() }
}

function Read-BHEAuditLog([string]$Path, [string]$SessionId = '') {
    try {
        if (!$SessionId) { $lines = @(Get-Content -LiteralPath $Path -Tail 100 -Encoding UTF8 -ErrorAction Stop) }
        else {
            $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop | Where-Object {
                try { ($null -ne $_) -and (($_ | ConvertFrom-Json -ErrorAction Stop).SessionId -eq $SessionId) } catch { $false }
            } | Select-Object -Last 100)
        }
    }
    catch { return @{ Available = $false; Entries = @(); InvalidLines = 0 } }
    $invalid = 0
    $entries = @(foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $entry = $line | ConvertFrom-Json -ErrorAction Stop
            if (!(Get-BHEField $entry 'AtUtc') -or !(Get-BHEField $entry 'Action')) { throw 'Invalid audit entry.' }
            [pscustomobject]@{ AtUtc = $entry.AtUtc; Action = $entry.Action
                SessionId = (Get-BHEField $entry 'SessionId')
                BaseUrl = (Get-BHEField $entry 'BaseUrl'); LocalOperator = (Get-BHEField $entry 'LocalOperator')
                Details = (Get-BHEField $entry 'Details' | ConvertTo-Json -Depth 8 -Compress) }
        } catch { $invalid++ }
    })
    return @{ Available = $true; Entries = $entries; InvalidLines = $invalid }
}

function Read-BHERecentAudit($Session, [switch]$CurrentSession) {
    $lock = Open-BHEAuditLock $Session.Journal
    try {
        $boundary = Get-BHEField $Session 'AuditStartArchive'
        $archives = @(Get-BHEAuditArchives $Session.Journal | Where-Object { !$CurrentSession -or !$boundary -or $_.Name -gt $boundary })
        $paths = @($Session.Journal) + @($archives | ForEach-Object FullName)
        $entries = @(); $invalid = 0; $available = $false
        foreach ($path in $paths) {
            $filter = ''
            if ($CurrentSession) { $filter = $Session.Id }
            $part = Read-BHEAuditLog -Path $path -SessionId $filter
            if (!$part.Available) { continue }
            $available = $true; $invalid += $part.InvalidLines
            $entries = @($part.Entries) + $entries
            if ($entries.Count -ge 100) { break }
        }
        return @{ Available = $available; Entries = @($entries | Select-Object -Last 100); InvalidLines = $invalid }
    } finally { $lock.Dispose() }
}

function Show-BHEAuditLog($Session) {
    $choice = Read-Host 'Audit log: [C]urrent session [L]atest events across sessions [A]rchives/legacy logs [R]eturn to main menu (Q cancels)'
    $path = $Session.Journal; $viewedSession = ''; $mode = 'Recent'
    if ($choice -eq 'C') { $viewedSession = $Session.Id; $mode = 'CurrentSession' }
    elseif ($choice -in @('A','P')) {
        $root = [IO.Path]::GetDirectoryName($Session.Journal)
        try {
            $files = @(Get-BHEAuditArchives $Session.Journal)
            # Older per-run logs remain readable; they are never migrated or pruned automatically.
            $legacy = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
                Where-Object { $_.Name -match '^\d{8}T\d{6}Z-[a-f0-9]{32}$' -and !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
                ForEach-Object { $old = Join-Path $_.FullName 'audit.jsonl'; if (Test-Path -LiteralPath $old -PathType Leaf) { Get-Item -LiteralPath $old } })
            $files = @(@($files) + @($legacy) | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20)
        } catch { Write-Host 'Archived logs could not be listed.'; return }
        if ($files.Count -eq 0) { Write-Host 'No archived or legacy audit logs found.'; return }
        Write-Host 'Archives and legacy logs (up to 20, newest first):'
        for ($index = 0; $index -lt $files.Count; $index++) { Write-Host "[$($index + 1)] $($files[$index].FullName)" }
        $answer = Read-Host 'Select a log number, [R]eturn to main menu, or Q to cancel'
        if ($answer -in @('R','Q','')) { return }
        $number = 0
        if (![int]::TryParse($answer, [ref]$number) -or $number -lt 1 -or $number -gt $files.Count) { Write-Host 'Invalid log number.'; return }
        $path = $files[$number - 1].FullName; $mode = 'Archive'
    } elseif ($choice -ne 'L') {
        if ($choice -notin @('R','Q','')) { Write-Host 'Invalid audit-log option.' }
        return
    }
    if ($mode -eq 'Archive') {
        $lock = Open-BHEAuditLock $Session.Journal
        try { $log = Read-BHEAuditLog $path } finally { $lock.Dispose() }
    } else { $log = Read-BHERecentAudit $Session -CurrentSession:($mode -eq 'CurrentSession') }
    if (!$log.Available) {
        Write-Host 'Audit log is unavailable or unreadable.'
        Write-BHEAudit $Session 'AuditLogUnavailable' @{ Mode = $mode }; return
    }
    Write-Host "Audit log: $path | view: $mode"
    Write-Host "Showing $($log.Entries.Count) recent valid events, oldest first (maximum 100). Full events remain in the active file and retained archives."
    if ($log.InvalidLines -gt 0) { Write-Host "Skipped $($log.InvalidLines) malformed/incomplete line(s); raw content was not displayed." }
    $log.Entries | Format-List AtUtc,SessionId,BaseUrl,LocalOperator,Action,Details | Out-Host
    $log.Entries | Group-Object Action | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name,$_.Count) }
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host 'Revoked = API returned HTTP 200. IneligibleSelection/cancellation = no deletion sent. FailedOrUnknown requires checking a fresh inventory.'
    Write-BHEAudit $Session 'AuditLogViewed' @{ Mode = $mode; ViewedSessionId = $viewedSession; File = $path; DisplayedCount = $log.Entries.Count; InvalidLines = $log.InvalidLines }
    [void](Read-Host 'Press Enter to return to the API token list')
}
function Get-BHECollectorTokens($Context, $Session) {
    $byTokenId = @{}; $conflicts = @{}; $complete = $true
    $clients = @(); $seenClients = @{}; $skip = 0; $expectedCount = $null
    try {
        do {
            $response = Invoke-BHERequest $Context GET ("/api/v2/clients?skip=$skip&limit=100")
            $count = Get-BHEField $response 'count'
            if ([string]$count -notmatch '^\d+$' -or [long]$count -gt 1000 -or
                $null -eq $response.PSObject.Properties['data'] -or $response.data -isnot [array]) {
                throw 'Unsupported collector collection; maximum supported inventory is 1000 clients.'
            }
            if ($null -eq $expectedCount) { $expectedCount = [int]$count }
            if ([int]$count -ne $expectedCount) { throw 'Collector inventory changed during pagination.' }
            $page = @($response.data)
            if ($page.Count -gt 100 -or ($page.Count -eq 0 -and $skip -lt $expectedCount)) { throw 'Unexpected collector page.' }
            foreach ($client in $page) {
                $id = ConvertTo-BHEUuid (Get-BHEField $client 'id')
                if (!$id -or $seenClients.ContainsKey($id)) { throw 'Invalid/duplicate collector ID.' }
                $seenClients[$id] = $true
                $clients += $id
            }
            $skip += $page.Count
        } while ($skip -lt $expectedCount)
        if ($clients.Count -ne $expectedCount) { throw 'Collector count mismatch.' }
    } catch {
        Write-Host 'Collector lookup unavailable; unresolved tokens remain Unknown and excluded from cleanup.'
        Write-BHEAudit $Session 'CollectorLookupUnavailable'
        return @{ ByTokenId = @{}; Complete = $false }
    }
    foreach ($id in $clients) {
        try {
            # List responses can redact token IDs. Match only the exact ID returned by GET detail.
            $response = Invoke-BHERequest $Context GET ('/api/v2/clients/' + $id)
            $client = Get-BHEField $response 'data'
            if ((ConvertTo-BHEUuid (Get-BHEField $client 'id')) -ne $id) { throw 'Collector detail ID mismatch.' }
            $tokenId = ConvertTo-BHEUuid (Get-BHEField (Get-BHEField $client 'token') 'id')
            if (!$tokenId) { throw 'Collector token ID not available.' }
            if ($conflicts.ContainsKey($tokenId)) { throw 'Ambiguous collector token mapping.' }
            if ($byTokenId.ContainsKey($tokenId)) {
                $byTokenId.Remove($tokenId); $conflicts[$tokenId] = $true
                throw 'Ambiguous collector token mapping.'
            }
            # Retain only display metadata. Never return or persist raw collector/token objects.
            $byTokenId[$tokenId] = [pscustomobject]@{
                Id = $id; Name = [string](Get-BHEField $client 'name')
                Type = [string](Get-BHEField $client 'type')
                LastCheckin = [string](Get-BHEField $client 'last_checkin')
            }
        } catch {
            $complete = $false
            Write-BHEAudit $Session 'CollectorDetailUnavailable' @{ ClientId = $id }
        }
    }
    Write-BHEAudit $Session 'CollectorLookupCompleted' @{ ClientCount = $clients.Count; MatchedTokenCount = $byTokenId.Count; Complete = $complete }
    if (!$complete) { Write-Host 'Some collector details are unavailable; unresolved tokens remain Unknown.' }
    return @{ ByTokenId = $byTokenId; Complete = $complete }
}

function Get-BHEInventory($Context, $Policy, $Session) {
    $tokens = @(Get-BHETokens $Context)
    $usersById = @{}
    $enrichmentAvailable = $true
    try {
        $response = Invoke-BHERequest $Context GET '/api/v2/bloodhound-users'
        $userData = Get-BHEField $response 'data'
        if ($null -eq $userData -or $null -eq $userData.PSObject.Properties['users']) { throw 'Expected user data.' }
        $users = $userData.users
        if ($null -eq $users -or $users -isnot [System.Array]) { throw 'Expected user array.' }
        foreach ($user in $users) {
            $ownerId = ConvertTo-BHEUuid (Get-BHEField $user 'id')
            if ($ownerId) {
                if ($usersById.ContainsKey($ownerId)) { throw 'Duplicate user IDs.' }
                $usersById[$ownerId] = $user
            }
        }
    } catch {
        # Enrichment failure must not be interpreted as a token-list failure or an empty tenant.
        $usersById = @{}
        $enrichmentAvailable = $false
    }
    if (!$enrichmentAvailable) {
        Write-Host 'Owner/role lookup unavailable; showing Unknown. Token visibility still depends on caller permissions.'
        Write-BHEAudit $Session 'OwnerLookupUnavailable'
    }
    $collectorLookup = Get-BHECollectorTokens $Context $Session
    $seen = @{}
    $rows = @(foreach ($token in $tokens) {
        $row = Get-BHETokenAssessment $token $Policy
        if ($row.TokenId) {
            if ($seen.ContainsKey($row.TokenId)) { throw 'Duplicate token IDs in inventory; stopping.' }
            $seen[$row.TokenId] = $true
        }
        $ownerName = 'Unknown'; $roles = 'Unknown'
        $tokenType = 'Unknown'; $collectorId = ''; $collectorType = ''; $collectorName = ''; $lastCheckin = ''
        if ($row.UserId) { $tokenType = 'User' }
        if ($row.TokenId -and $collectorLookup.ByTokenId.ContainsKey($row.TokenId)) {
            $collector = $collectorLookup.ByTokenId[$row.TokenId]
            $tokenType = 'Collector'; $collectorId = $collector.Id; $collectorType = $collector.Type
            $collectorName = $collector.Name; $lastCheckin = $collector.LastCheckin
            $ownerName = $collectorName
            if ([string]::IsNullOrWhiteSpace($ownerName)) { $ownerName = $collectorId }
            $roles = 'N/A'
            # Preserve the actual nullable token name separately from its collector display name.
            if ([string]::IsNullOrWhiteSpace($row.Name)) { $row.Name = $ownerName }
            $row.Reason = 'CollectorTokenProtected'
        }
        if ($tokenType -eq 'User' -and $usersById.ContainsKey($row.UserId)) {
            $user = $usersById[$row.UserId]
            $ownerName = [string](Get-BHEField $user 'principal_name')
            if ([string]::IsNullOrWhiteSpace($ownerName)) {
                $ownerName = [string](ConvertFrom-BHENullable (Get-BHEField $user 'email_address') 'String')
            }
            if ([string]::IsNullOrWhiteSpace($ownerName)) { $ownerName = 'Unknown' }
            $roleNames = @(foreach ($role in @(Get-BHEField $user 'roles')) {
                $roleName = [string](Get-BHEField $role 'name')
                if (![string]::IsNullOrWhiteSpace($roleName)) { $roleName }
            })
            if ($roleNames.Count -gt 0) { $roles = ($roleNames | Sort-Object -Unique) -join ', ' }
        }
        $row | Add-Member -NotePropertyName Owner -NotePropertyValue $ownerName
        $row | Add-Member -NotePropertyName Role -NotePropertyValue $roles
        $row | Add-Member -NotePropertyName TokenType -NotePropertyValue $tokenType
        $row | Add-Member -NotePropertyName TokenName -NotePropertyValue ([string](ConvertFrom-BHENullable (Get-BHEField $token 'name') 'String'))
        $row | Add-Member -NotePropertyName CollectorId -NotePropertyValue $collectorId
        $row | Add-Member -NotePropertyName CollectorType -NotePropertyValue $collectorType
        $row | Add-Member -NotePropertyName CollectorName -NotePropertyValue $collectorName
        $row | Add-Member -NotePropertyName CollectorLastCheckin -NotePropertyValue $lastCheckin
        $row
    })
    $snapshot = 'inventory-' + [guid]::NewGuid().ToString('N') + '.json'
    Write-BHEJsonFile (Join-Path $Session.Directory $snapshot) ([ordered]@{
        BaseUrl = $Context.BaseUrl; ObservedAtUtc = $Policy.Now.ToString('o'); Days = $Policy.Days
        CutoffUtc = $Policy.Cutoff.ToString('o'); ScopeUserIds = @($Policy.UserId)
        ExcludedUserIds = @($Policy.ExcludeUserId); ExcludedTokenIds = @($Policy.ExcludeTokenId)
        OwnerLookupAvailable = $enrichmentAvailable; CollectorLookupComplete = $collectorLookup.Complete; Tokens = $rows
    })
    Write-BHEAudit $Session 'InventoryLoaded' @{ Snapshot = (Join-Path $Session.Id $snapshot); VisibleCount = $rows.Count
        EligibleCount = @($rows | Where-Object Reason -eq 'Eligible').Count; Days = $Policy.Days }
    return $rows
}

function Get-BHEView($Rows, [string]$Sort = 'Oldest', [switch]$EligibleOnly, [string]$Search = '') {
    $filtered = @($Rows | Where-Object {
        (!$EligibleOnly -or $_.Reason -eq 'Eligible') -and
        (!$Search -or (($_.Name, $_.Owner, $_.Role, $_.TokenId, $_.UserId, $_.Reason,
            (Get-BHEField $_ 'TokenType'), (Get-BHEField $_ 'CollectorType'), (Get-BHEField $_ 'CollectorName')) -join ' ').IndexOf($Search, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    })
    # Parse timestamps so mixed UTC offsets sort chronologically, rather than lexically.
    # Unknown/year-one values appear last in both access-time sort directions.
    $unknown = @{ Expression = { $time = ConvertTo-BHETime $_.LastAccess; if ($null -eq $time -or $time.Year -le 1) { 1 } else { 0 } } }
    switch ($Sort) {
        'Newest' { $filtered | Sort-Object $unknown,@{ Expression = { ConvertTo-BHETime $_.LastAccess }; Descending = $true },TokenId }
        'Name' { $filtered | Sort-Object Name,TokenId }
        'Owner' { $filtered | Sort-Object Owner,Name,TokenId }
        'Role' { $filtered | Sort-Object Role,Owner,Name,TokenId }
        'Type' { $filtered | Sort-Object TokenType,Name,TokenId }
        default { $filtered | Sort-Object $unknown,@{ Expression = { ConvertTo-BHETime $_.LastAccess } },TokenId }
    }
}

function Show-BHEView($Rows) {
    $display = @(for ($index = 0; $index -lt $Rows.Count; $index++) {
        [pscustomobject][ordered]@{ Row = $index + 1; TokenType = $Rows[$index].TokenType; Name = $Rows[$index].Name
            Owner = $Rows[$index].Owner; Role = $Rows[$index].Role
            LastAccess = $Rows[$index].LastAccess; Status = $Rows[$index].Reason }
    })
    Write-Host "Displayed tokens: $($Rows.Count). Table text can wrap; use token details or JSON export for full metadata."
    $display | Format-Table -AutoSize -Wrap | Out-Host
}

function Invoke-BHERevocation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Context, $Policy, $Rows, $Session, [int]$MaxRevocations, [switch]$Simulation)
    if ($Rows.Count -eq 0) { Write-Host 'No rows in this view.'; return }
    if ($Simulation) {
        Write-Host 'Dry run/WhatIf: revocation disabled. No DELETE requests sent.'
        Write-BHEAudit $Session 'RevocationBlockedBySimulation'
        return
    }
    $selection = Read-Host 'Select comma-separated row numbers, A for all eligible rows in this view, [R]eturn to main menu, or Q to cancel'
    if ($selection -in @('Q','R') -or [string]::IsNullOrWhiteSpace($selection)) {
        Write-BHEAudit $Session 'SelectionCancelled'; return
    }
    if ($selection -eq 'A') { $selected = @($Rows | Where-Object Reason -eq 'Eligible') }
    else {
        $indexes = @($selection.Split(',') | ForEach-Object {
            $number = 0
            if (![int]::TryParse($_.Trim(), [ref]$number) -or $number -lt 1 -or $number -gt $Rows.Count) { -1 }
            else { $number - 1 }
        } | Select-Object -Unique)
        if (-1 -in $indexes) { Write-Host 'Invalid selection; nothing revoked.'; Write-BHEAudit $Session 'InvalidSelection'; return }
        $selected = @($indexes | ForEach-Object { $Rows[$_] })
    }
    if ($selected.Count -eq 0 -or @($selected | Where-Object Reason -ne 'Eligible').Count -gt 0) {
        Write-Host 'Select only eligible stale tokens; nothing revoked.'
        Write-BHEAudit $Session 'IneligibleSelection'; return
    }
    if ($selected.Count -gt $MaxRevocations) {
        Write-BHEAudit $Session 'RevocationLimitExceeded' @{ SelectedCount = $selected.Count; Limit = $MaxRevocations }
        Write-Host "Selected count exceeds MaxRevocations ($MaxRevocations); nothing revoked."; return
    }
    Write-Host "Selected $($selected.Count) token(s) for irreversible revocation:"
    $selected | Format-List TokenId,UserId,Name,Owner,Role,CreatedAt,LastAccess | Out-Host
    $phrase = "REVOKE $($selected.Count)"
    if ((Read-Host "Type '$phrase' to proceed, [R]eturn to main menu, or Q to cancel") -cne $phrase) {
        Write-BHEAudit $Session 'ConfirmationCancelled' @{ SelectedTokenIds = @($selected.TokenId) }; return
    }
    $selectionFile = 'selection-' + [guid]::NewGuid().ToString('N') + '.json'
    Write-BHEJsonFile (Join-Path $Session.Directory $selectionFile) @($selected)
    Write-BHEAudit $Session 'SelectionApproved' @{ SelectedTokenIds = @($selected.TokenId); Snapshot = (Join-Path $Session.Id $selectionFile) }
    foreach ($row in $selected) {
        if (!$PSCmdlet.ShouldProcess("$($Context.BaseUrl) token $($row.TokenId) owned by $($row.UserId)", 'Revoke user API token')) {
            Write-BHEAudit $Session 'ShouldProcessDeclined' @{ TokenId = $row.TokenId }; continue
        }
        $current = @(Get-BHETokens $Context $row.TokenId)
        if ($current.Count -ne 1 -or (ConvertTo-BHEUuid (Get-BHEField $current[0] 'id')) -ne $row.TokenId) {
            Write-BHEAudit $Session 'RevalidationFailed' @{ TokenId = $row.TokenId }
            throw 'Revalidation did not return exactly the requested token; stopping.'
        }
        $check = Get-BHETokenAssessment $current[0] $Policy
        if ($check.Reason -ne 'Eligible' -or $check.UserId -ne $row.UserId -or
            $check.LastAccess -cne $row.LastAccess -or $check.CreatedAt -cne $row.CreatedAt -or $check.Name -cne $row.Name) {
            Write-BHEAudit $Session 'SkippedChanged' @{ TokenId = $row.TokenId; UserId = $row.UserId }
            Write-Host "Skipped changed token $($row.TokenId)."; continue
        }
        Write-BHEAudit $Session 'RevocationIntent' @{ TokenId = $row.TokenId; UserId = $row.UserId; LastAccess = $row.LastAccess }
        try { Invoke-BHERequest $Context DELETE ('/api/v2/tokens/' + $row.TokenId) }
        catch {
            Write-BHEAudit $Session 'FailedOrUnknown' @{ TokenId = $row.TokenId; UserId = $row.UserId }
            throw 'Revocation failed or its outcome is unknown. Stopped; inspect a fresh inventory before retrying.'
        }
        Write-BHEAudit $Session 'Revoked' @{ TokenId = $row.TokenId; UserId = $row.UserId; HttpStatus = 200 }
        Write-Host "Revoked $($row.TokenId)."
    }
}

function Invoke-BHETokenCleanup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$BaseUrl, [int]$Days = 90,
        [string]$TokenId, [string]$TokenKey, [string]$BearerToken,
        [string]$EnvFile, [switch]$NoEnvFile,
        [string[]]$UserId = @(), [string[]]$ExcludeUserId = @(), [string[]]$ExcludeTokenId = @(),
        [switch]$DryRun, [switch]$Revoke, [switch]$NonInteractive, [int]$MaxRevocations = 20,
        [string]$OutputDirectory, [int]$TimeoutSec = 30,
        [int]$AuditMaxSizeMB = 10, [int]$AuditArchiveCount = 0
    )
    $ErrorActionPreference = 'Stop'
    if ($AuditMaxSizeMB -lt 1 -or $AuditMaxSizeMB -gt 1024 -or $AuditArchiveCount -lt 0 -or $AuditArchiveCount -gt 10000) { throw 'Invalid audit rotation settings.' }
    if (!$PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $script:BHECleanupDirectory 'reports' }
    $configuration = Resolve-BHEConfiguration -Explicit $PSBoundParameters -EnvFile $EnvFile -NoEnvFile:$NoEnvFile
    $BaseUrl = $configuration.BaseUrl; $TokenId = $configuration.TokenId
    $TokenKey = $configuration.TokenKey; $BearerToken = $configuration.BearerToken
    if ($Days -lt 1 -or $Days -gt 36500 -or $MaxRevocations -lt 1 -or $MaxRevocations -gt 1000) { throw 'Invalid policy limits.' }
    $uri = ConvertTo-BHEOrigin $BaseUrl
    if ($BearerToken -and ($TokenKey -or $TokenId)) { throw 'Choose bearer authentication OR a signing token pair; clear unused credentials in parameters, .env, or environment variables.' }
    if (!$BearerToken -and (!$TokenKey -or !(ConvertTo-BHEUuid $TokenId))) { throw 'Provide a signing token ID/key pair or a bearer token.' }
    foreach ($value in @($UserId) + @($ExcludeUserId) + @($ExcludeTokenId)) {
        if (!(ConvertTo-BHEUuid $value)) { throw 'User and token scope IDs must be nonzero UUIDs.' }
    }
    $context = @{ BaseUrl = $uri.GetLeftPart([UriPartial]::Authority); TokenId = $TokenId
        TokenKey = $TokenKey; BearerToken = $BearerToken; TimeoutSec = $TimeoutSec }
    $now = [DateTimeOffset]::UtcNow
    $policy = @{ Now = $now; Cutoff = $now.AddDays(-$Days); TokenId = $TokenId
        UserId = @($UserId); ExcludeUserId = @($ExcludeUserId); ExcludeTokenId = @($ExcludeTokenId) }
    if ($NonInteractive -and $Revoke) { throw 'NonInteractive is report-only; omit -Revoke.' }
    $policy.Days = $Days
    $sessionId = $now.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $sessionId
    [void][IO.Directory]::CreateDirectory($runDirectory)
    $session = @{ Id = $sessionId; Directory = $runDirectory; Journal = (Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'audit.jsonl')
        BaseUrl = $context.BaseUrl; Operator = [Environment]::UserName; SigningTokenId = $TokenId
        AuditMaxBytes = ([long]$AuditMaxSizeMB * 1MB); AuditArchiveCount = $AuditArchiveCount }
    Write-Host "Tenant: $($context.BaseUrl)"
    Write-Host "Session snapshots: $runDirectory"
    Write-Host "Shared audit log: $($session.Journal) | rotate at $AuditMaxSizeMB MB | retained archives: $AuditArchiveCount (0 = all)"
    Write-BHEAudit $session 'SessionStarted' @{ Days = $Days; DryRun = [bool]$DryRun
        WhatIf = [bool]$WhatIfPreference; NonInteractive = [bool]$NonInteractive; MaxRevocations = $MaxRevocations
        SnapshotDirectory = $session.Id; AuditMaxSizeMB = $AuditMaxSizeMB; AuditArchiveCount = $AuditArchiveCount }
    $sort = 'Oldest'; $eligibleOnly = $false; $search = ''; $refresh = $true
    $simulation = $DryRun -or $WhatIfPreference
    try {
        while ($true) {
            if ($refresh) {
                $policy.Now = [DateTimeOffset]::UtcNow
                $policy.Cutoff = $policy.Now.AddDays(-$policy.Days)
                $report = @(Get-BHEInventory $context $policy $session)
                $refresh = $false
            }
            $view = @(Get-BHEView $report -Sort $sort -EligibleOnly:$eligibleOnly -Search $search)
            Write-Host "Visible tokens: $($report.Count); eligible: $(@($report | Where-Object Reason -eq 'Eligible').Count). Visibility depends on caller permissions."
            Write-Host "Policy: last_access strictly before $($policy.Cutoff.ToString('o')) ($($policy.Days) days). Sort: $sort | stale only: $eligibleOnly | search: $search"
            if ($simulation) { Write-Host 'DRY RUN / WHATIF: revocation is disabled.' }
            Show-BHEView $view
            Write-BHEAudit $session 'ViewDisplayed' @{ Sort = $sort; EligibleOnly = $eligibleOnly; Search = $search; DisplayedCount = $view.Count }
            if ($NonInteractive) { Write-Host 'Report only. No DELETE requests sent.'; return }
            # -Revoke retains the previous direct-selection entry point.
            if ($Revoke) {
                Invoke-BHERevocation -Context $context -Policy $policy -Rows $view -Session $session -MaxRevocations $MaxRevocations -Simulation:$simulation
                return
            }
            Write-Host '[1] All tokens  [2] Eligible stale tokens  [3] Sort  [4] Change age threshold'
            Write-Host '[5] Refresh  [6] Revoke selected stale tokens  [7] Export current view'
            Write-Host '[8] Search/filter  [9] Token details  [10] Audit log  [Q] Quit'
            $choice = Read-Host 'Choose an option'
            switch ($choice) {
                '1' { $eligibleOnly = $false; $search = '' }
                '2' { $eligibleOnly = $true }
                '3' {
                    $answer = Read-Host 'Sort: [1] Oldest access [2] Newest access [3] Name [4] Owner [5] Role [6] Token type [R]eturn to main menu (Q cancels)'
                    $sorts = @{ '1' = 'Oldest'; '2' = 'Newest'; '3' = 'Name'; '4' = 'Owner'; '5' = 'Role'; '6' = 'Type' }
                    if ($sorts.ContainsKey($answer)) { $sort = $sorts[$answer]; Write-BHEAudit $session 'SortChanged' @{ Sort = $sort } }
                    elseif ($answer -notin @('R','Q','')) { Write-Host 'Invalid sort option.' }
                }
                '4' {
                    $answer = Read-Host 'Enter age in days (1-36500), [R]eturn to main menu, or Q to cancel'
                    if ($answer -notin @('R','Q','')) {
                        $newDays = 0
                        if ([int]::TryParse($answer, [ref]$newDays) -and $newDays -ge 1 -and $newDays -le 36500) {
                            $policy.Days = $newDays; $refresh = $true
                            Write-BHEAudit $session 'PolicyChanged' @{ Days = $newDays }
                        } else { Write-Host 'Invalid age threshold; policy unchanged.' }
                    }
                }
                '5' { $refresh = $true; Write-BHEAudit $session 'RefreshRequested' }
                '6' {
                    Invoke-BHERevocation -Context $context -Policy $policy -Rows $view -Session $session -MaxRevocations $MaxRevocations -Simulation:$simulation
                    # Discard all row selections and refresh after any deletion attempt/cancellation.
                    $refresh = $true
                }
                '7' {
                    $export = 'view-' + [guid]::NewGuid().ToString('N') + '.json'
                    Write-BHEJsonFile (Join-Path $runDirectory $export) @($view)
                    Write-BHEAudit $session 'ViewExported' @{ File = (Join-Path $session.Id $export); Count = $view.Count }
                    Write-Host "Exported $($view.Count) token(s): $(Join-Path $runDirectory $export)"
                }
                '8' {
                    $answer = Read-Host 'Search name, owner, role, IDs, status, or token/collector type (blank clears), [R]eturn to main menu, or Q to cancel'
                    if ($answer -notin @('R','Q')) { $search = $answer; Write-BHEAudit $session 'SearchChanged' @{ Search = $search } }
                }
                '9' {
                    $answer = Read-Host 'Enter row number for full details, [R]eturn to main menu, or Q to cancel'
                    if ($answer -notin @('R','Q','')) {
                        $number = 0
                        if ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $view.Count) {
                            $view[$number - 1] | Format-List * | Out-Host
                            Write-BHEAudit $session 'DetailsViewed' @{ TokenId = $view[$number - 1].TokenId }
                        } else { Write-Host 'Invalid row number.' }
                    }
                }
                '10' { Show-BHEAuditLog $session }
                'Q' { Write-BHEAudit $session 'QuitRequested'; return }
                default { Write-Host 'Invalid menu option; choose 1-10 or Q.' }
            }
        }
    } catch {
        # Never persist raw exception/server bodies or credentials in the audit log.
        Write-BHEAudit $session 'SessionStoppedOnError' @{ Detail = 'Operation failed; no automatic retry. Inspect inventory and prior audit entries.' }
        throw
    } finally { Write-BHEAudit $session 'SessionEnded' }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-BHETokenCleanup @PSBoundParameters }
