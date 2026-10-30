# BloodHound user API token cleanup

> **Disclaimer:** This tool is a vibe-coded example of how to use the BloodHound Enterprise (BHE) API to revoke API keys. Use it at your own risk. It is not supported by SpecterOps.

PowerShell 5.1+ utility for authorized tenant administration. Running the script opens an interactive token-management menu. It lists all tokens visible to the caller and only permits revocation of user tokens whose `last_access` is strictly older than the configured age.

## Interactive use

By default, the script loads `.env` from the script's directory, even when launched from another working directory. Copy the credential-free [.env.example](.env.example) to `.env` beside the script, then uncomment and fill in the appropriate assignments:

```dotenv
BHE_URL=https://your-tenant.bloodhoundenterprise.io
BHE_TOKEN_ID=your-token-id
BHE_TOKEN_KEY=your-token-key
BHE_BEARER_TOKEN=
```

Supported settings (also available as process environment variables):

- `BHE_URL`: HTTPS tenant origin without an API path. Local Docker instances may use HTTP on a loopback address or `localhost`, for example `http://127.0.0.1:8080`.
- `BHE_TOKEN_ID` and `BHE_TOKEN_KEY`: request-signing credentials.
- Alternatively, `BHE_BEARER_TOKEN`: an existing bearer token. Set `BHE_TOKEN_ID=` and `BHE_TOKEN_KEY=` when using bearer authentication to suppress inherited signing credentials.

Precedence is **explicit parameter > .env value > process environment**, independently for each setting. An explicitly empty value clears that setting rather than falling back. If the default `.env` is absent, process environment variables still work. An explicitly selected missing/unreadable file, duplicate/unsupported key, or malformed assignment stops execution before API access.

`.env` credentials are plaintext: restrict access and keep real secrets out of source control and command history. `.env` and `.env.*` are ignored by Git, with `.env.example` allowed. Values are literal: optional matching single/double quotes are stripped, but `$`, backticks, `#`, and `=` within values are preserved. No expressions, variable expansion, escape decoding, multiline values, or inline comments are supported. Use separate lines beginning with `#` for comments. The optional `export KEY=value` form is accepted. Loading a file does not modify the process environment. The script does not perform username/password login.

```powershell
# Default interactive menu, initial stale threshold 90 days.
.\Remove-BHEStaleAPITokens.ps1

# Use a different configuration file (relative paths resolve from the working directory).
.\Remove-BHEStaleAPITokens.ps1 -EnvFile .\.env.test

# Ignore .env and use explicit parameters/process environment.
.\Remove-BHEStaleAPITokens.ps1 -NoEnvFile

# Local Docker test (use the port published by your container).
.\Remove-BHEStaleAPITokens.ps1 -BaseUrl http://127.0.0.1:8080 -DryRun

# Same menu, with revocation disabled for the entire session.
.\Remove-BHEStaleAPITokens.ps1 -Days 120 -DryRun

# Prompt-free report for scheduled auditing; cannot revoke.
.\Remove-BHEStaleAPITokens.ps1 -Days 120 -NonInteractive

# Restrict eligibility to a user and protect an integration token.
.\Remove-BHEStaleAPITokens.ps1 -Days 120 `
    -UserId '11111111-1111-1111-1111-111111111111' `
    -ExcludeTokenId '22222222-2222-2222-2222-222222222222'
```

### Example startup output

```text
.\Remove-BHEStaleAPITokens.ps1
Tenant: https://your-tenant.bloodhoundenterprise.io
Session snapshots: C:\Git\RemoveBHEStaleAPI\reports\20261030T155041Z-a301982f7b4f435092a03a9ccb69793e
Shared audit log: C:\Git\RemoveBHEStaleAPI\reports\audit.jsonl | rotate at 10 MB | retained archives: 0 (0 = all)
Visible tokens: 17; eligible: 6. Visibility depends on caller permissions.
Policy: last_access strictly before 2026-08-01T15:50:41.5880602+00:00 (90 days). Sort: Oldest | stale only: False | search:
Displayed tokens: 17. Table text can wrap; use token details or JSON export for full metadata.

Row TokenType Name                            Owner             Role          LastAccess                  Status
--- --------- ----                            -----             ----          ----------                  ------
  1 Collector SharpHound Client               SharpHound Client N/A           2025-09-02T14:36:24.684967Z CollectorTokenProtected
  2 User      Demo_pvt_token_Bob              Bob               Power User    2025-10-22T13:23:17.789375Z Eligible
  3 Collector DefenderK-SHS                   DefenderK-SHS     N/A           2025-11-24T09:34:39.15771Z  CollectorTokenProtected
  4 Collector AzureHound Client               AzureHound Client N/A           2026-03-17T14:51:53.430403Z CollectorTokenProtected
  5 User      api_test                        api_audit         Power User    2026-05-08T10:22:15.397065Z Eligible
  6 User      splunk_api_token                splunk_api        Administrator 2026-06-11T16:07:51.494199Z Eligible
  7 User      splunk-bhe-poc-20260615T081508Z splunk_api        Administrator 2026-06-15T08:15:08.467127Z Eligible
  8 User      API_SPLUNK_ROTATE_TEST          admin             Administrator 2026-06-15T08:15:08.481417Z Eligible
  9 User      API_Import                      admin             Administrator 2026-07-09T09:49:30.351105Z Eligible
 10 User      API_TierZeroExport              admin             Administrator 2026-08-03T14:54:35.557188Z Recent
 11 User      MCP_Token                       admin             Administrator 2026-08-03T14:55:02.742614Z Recent
 12 User      api_test                        Bob               Power User    2026-10-16T15:31:14.227441Z Recent
 13 User      test_token                      Test1             Power User    2026-10-16T15:54:39.679069Z Recent
 14 Collector okta                            okta              N/A           2026-10-30T15:50:16.137589Z CollectorTokenProtected
 15 Collector github                          github            N/A           2026-10-30T15:50:20.242204Z CollectorTokenProtected
 16 Collector jamf                            jamf              N/A           2026-10-30T15:50:37.710632Z CollectorTokenProtected
 17 User      Audit_test                      admin             Administrator 2026-10-30T15:50:41.598351Z ExecutingToken


[1] All tokens  [2] Eligible stale tokens  [3] Sort  [4] Change age threshold
[5] Refresh  [6] Revoke selected stale tokens  [7] Export current view
[8] Search/filter  [9] Token details  [10] Audit log  [Q] Quit
Choose an option:
```

The initial view includes **TokenType**, name, owner, role, last access, and eligibility status, with numbered rows and totals. TokenType is `User` when the token has a valid user-owner UUID, `Collector` when its exact token ID matches a collector detail record, and `Unknown` when neither can be established. Collector identification takes precedence if both are present, and the token is protected.

**Role means the owning user's current role**, rather than a separate permission assigned to the token. For collector tokens, Owner shows the collector name (or ID if unnamed) and Role is `N/A`. A blank token Name is filled with the collector name for display; JSON/details preserve the original label in `TokenName`, alongside `CollectorId`, `CollectorName`, `CollectorType`, and `CollectorLastCheckin`. Matched collector tokens have status **`CollectorTokenProtected`** and cannot be revoked through this user-token cleanup utility. Unresolved tokens retain `Unknown` owner/role and remain ineligible.

Collector lookup uses the paginated client list plus individual collector GETs, because list responses may redact token IDs. Names/timestamps are never used to guess a match. Missing permissions, unsupported endpoints, malformed responses, and unavailable detail records are audited; any confirmed matches are retained when individual detail lookups fail. Lookup is bounded to 1000 clients per refresh; larger or inconsistent collections leave collector lookup unavailable. The script continues user-token reporting even if collector lookup is unavailable.

| Option | Action |
| --- | --- |
| 1 | Show all visible tokens and clear the search |
| 2 | Show only eligible stale tokens, retaining the current search |
| 3 | Sort by last access oldest/newest, token name, owner, role, or token type |
| 4 | Change the age threshold and reload inventory |
| 5 | Refresh tokens and owner metadata |
| 6 | Select and revoke eligible stale tokens from the current view |
| 7 | Export the current filtered/sorted view to JSON |
| 8 | Search token name, owner, role, IDs, status, or token/collector type; blank clears |
| 9 | Display full metadata for a numbered row |
| 10 | View current-session events, recent events across sessions, or archived/legacy logs |
| Q | End the session |

Access times sort chronologically across UTC offsets. Unknown/never-used dates appear last in either time-sort direction. The console table can wrap; full metadata is available in option 9 and JSON exports. Changing the sort or filter renumbers rows; selection always uses the currently displayed view. All-token visibility does not make recent, protected, or unknown-date tokens eligible for deletion.

Submenus provide `[R]eturn to main menu` and `Q` cancellation. Revocation accepts comma-separated row numbers or `A` for all eligible tokens **in the current view**. Invalid or ineligible selections are rejected as a whole. The full selected metadata is displayed again, and the operator must type `REVOKE <count>` exactly. PowerShell then asks for high-impact confirmation per token. `-Confirm:$false` suppresses only that additional PowerShell prompt; selection and typed confirmation remain required. After a revocation operation or cancellation, the menu discards the selection and refreshes inventory.

`-WhatIf` opens the menu with revocation disabled, like `-DryRun`. `-NonInteractive` makes reporting prompt-free; combining it with `-Revoke` is rejected. For compatibility, `-Revoke` alone opens direct row selection and then exits. There is no unattended revocation mode.

Other settings: `-ExcludeUserId`, `-ExcludeTokenId`, `-OutputDirectory`, `-TimeoutSec` (default 30), `-MaxRevocations` (default 20, maximum 1000 **per selection operation**), `-AuditMaxSizeMB` (default 10, range 1-1024), and `-AuditArchiveCount` (default 0: keep all archives).

## Audit output

All sessions using the same output directory append to **`reports/audit.jsonl`**. Each event retains its session ID, tenant origin, and operator metadata. Inventory/selection/view snapshots stay in unique session directories; audit references include their relative session paths.

Use **option 10**, then `C` for current-session events, `L` for the latest events across sessions, or `A` to select an archive or an older per-run log. Current/recent views span the active file and retained archives and display up to 100 valid events in append order. Archive selection shows up to 20 files, newest first, and reads the selected file's last 100 lines. Malformed/incomplete lines are skipped without displaying raw contents; counts are shown where detected. `R` returns to the main menu; `Q` cancels. Viewing logs appends `AuditLogViewed` to the shared log. Archived/legacy files are not edited by the viewer (normal optional retention can still expire generated archives). This is the utility's local audit log, not the tenant-wide BloodHound audit log.

Before a complete entry would make the active file exceed **10 MiB**, the writer renames it to `audit-<UTC timestamp>-<unique-id>.jsonl` and opens a new active file. Change the threshold with `-AuditMaxSizeMB`. An individual event larger than the limit is kept whole; the next append rotates it. A shared exclusive `audit.jsonl.lock` file coordinates writes, rotation, retention, and viewer reads across processes; the lock handle is released after each operation. Failure to obtain the lock within five seconds or persist an entry stops the operation, including before a token DELETE. Use a local report directory for these filesystem-lock guarantees.

Archives are retained indefinitely by default. **Setting `-AuditArchiveCount N` to a positive number deletes older generated archives**, retaining the newest N after successful appends. Only generated archive filenames in the configured audit directory are eligible; old per-run logs and session snapshot folders are never pruned. Current-session views can only show entries still retained. Existing per-run logs are left in place and remain accessible through `A`; no automatic migration or deletion occurs.

```powershell
# Default: rotate at 10 MiB, retain every archive.
.\Remove-BHEStaleAPITokens.ps1

# Rotate at 25 MiB and explicitly retain only the newest 10 archives.
.\Remove-BHEStaleAPITokens.ps1 -AuditMaxSizeMB 25 -AuditArchiveCount 10
```

| File | Contents |
| --- | --- |
| `reports/audit.jsonl` | Shared active log, one JSON event per line across runs |
| `reports/audit-<timestamp>-<id>.jsonl` | Rotated archive |
| `reports/audit.jsonl.lock` | Coordination file; its presence alone does not mean a process holds the lock |
| `reports/<session>/inventory-<id>.json` | Complete visible-token inventory and classifications for each refresh, with UTC cutoff and scope/exclusions |
| `reports/<session>/selection-<id>.json` | Exact metadata selected and approved for a revocation operation |
| `reports/<session>/view-<id>.json` | Current filtered/sorted view, when option 7 is used |

Audit entries include UTC time, session ID, tenant origin, **local OS operator**, signing token ID when applicable, action, and relevant details. The local operator is not proof of the authenticated BloodHound identity. Events cover session start/end, inventory loads, unavailable owner lookup, view display/export, sorting/search/policy changes, refreshes, selection/confirmation cancellation, rejected selections, approved selection, declined PowerShell confirmation, revalidation failures, changed-token skips, revocation intent, HTTP-200 success, and failed/unknown outcomes. Errors stop the session and are recorded using a generic message rather than raw server bodies.

```powershell
# Inspect the shared active audit file.
Get-Content .\reports\audit.jsonl -Encoding UTF8 |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Select-Object AtUtc, Action, Details
```

Protect these files: they contain tenant/user/token identifiers, names, roles, and search text. Credentials, token keys, and raw user records are excluded. Evidence files are metadata snapshots, **not restorable credential backups**. Local logs are editable and are not a tamper-proof or transactional audit system; use the tenant's own audit records as additional evidence.

## Safety and request flow

1. Validate the origin, authentication configuration, and scope IDs. HTTPS is required for remote hosts; HTTP is allowed only for literal loopback IP addresses (including `127.0.0.1` and `[::1]`) and the exact hostname `localhost`. No DNS lookup is used to extend this exception. Create the session directory and audit log before making API calls.
2. Load visible tokens and attempt user/collector enrichment. If lookups are unavailable, retain unresolved token metadata with `Unknown` labels. Collector matches require exact token IDs from detail responses. Malformed token responses and duplicate token IDs stop the session.
3. Compute a fixed UTC cutoff for that inventory refresh. Require a valid nonzero user owner and usable access/creation timestamps. Allow creation to be up to **one second later than last access**, because initial access time can be assigned before the database sets creation time. Larger inconsistencies, future creation timestamps, and missing/invalid creation times remain `InvalidCreationTime`. An exact access-cutoff match is recent. Missing, malformed, timezone-free, future, or year-one/never-used access times remain ineligible. The one-second tolerance does not change the stale-access cutoff; creation age never substitutes for access age.
4. Protect the executing signing token, configured exclusions, and confirmed collector tokens. Tokens without a valid user owner are also ineligible. Collector endpoints are accessed using GET only; the utility does not change collectors or their credentials. For `deleted_at`, null/blank values and nullable objects with Boolean `Valid: false` mean no deletion timestamp. A nonempty timestamp, `Valid: true`, or an unrecognized representation is excluded as `DeletedOrUnknownDeletionState`; that status alone does not prove deletion.
5. Before each selected deletion, GET the exact token by ID. Require exactly one matching result, reassess eligibility, and skip tokens whose owner, name, creation time, or access timestamp changed since the preview.
6. Persist intent before DELETE. HTTP 200 records `Revoked`; an error records `FailedOrUnknown` and stops the batch without an automatic retry. Evidence-write failures also stop execution.

A dry run still makes authenticated GET requests and writes local evidence; the caller's own token access time may advance. HTTPS uses normal certificate validation, redirects are disabled, and requests have a timeout. Local HTTP works with `http://127.0.0.1:<published-port>`, `http://localhost:<published-port>`, or `http://[::1]:<published-port>` when that address reaches the container from the machine running PowerShell. Remote HTTP hosts, including private LAN addresses, are rejected. Revocation can interrupt an integration and is irreversible. User-backed service tokens are user tokens too: explicitly exclude integrations that run infrequently.

The API has no documented atomic conditional delete based on `last_access`. Revalidation reduces the race between last use and deletion but cannot eliminate it. `Revoked` means the server returned HTTP 200; the script does not test an old credential or independently verify deletion afterward. After an interrupted/ambiguous request, inspect a fresh inventory before retrying. With bearer authentication, use token exclusions to protect any integration credentials that must remain available.

## API contract

Checked against official published OpenAPI/source on 29 October 2026. Confirm the same contract in the deployed tenant's **API Explorer** before production use; public `main` may differ from the tenant version.

| Operation | Endpoint | Contract used |
| --- | --- | --- |
| Inventory | `GET /api/v2/tokens` | `data.tokens` array with token metadata |
| Owner/role enrichment | `GET /api/v2/bloodhound-users` | `data.users`, joined by `id`; `principal_name` and `roles[].name` |
| Collector inventory | `GET /api/v2/clients?skip=<offset>&limit=100` | Paginated `data` array with total `count` |
| Collector token matching | `GET /api/v2/clients/<UUID>` | `data.token.id` matched exactly to token inventory; display fields are whitelisted |
| Revalidation | `GET /api/v2/tokens?id=eq:<UUID>` | Exactly one matching token required |
| Revocation | `DELETE /api/v2/tokens/<UUID>` | HTTP **200**; no response body required |

Tenant-wide visibility and revoking another user's token require `auth:manage_users` permission (normally Administrator). Non-admin token lists are restricted to the caller. A successful list response does not prove tenant-wide coverage, and owner lookup may be unavailable for restricted callers. Owner roles are metadata, not a separate authorization check; the server enforces deletion permissions.

The token endpoint supports time predicates and user filters, but this utility classifies locally to retain unknown/excluded records in the report. The current token/user collections are unpaginated. Collector listing uses its documented pagination; the script does not invent pagination for the token/user endpoints.

Official references:

- [Token-list OpenAPI](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/tokens.tokens.yaml)
- [Token-delete OpenAPI](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/tokens.tokens.id.yaml)
- [User-list OpenAPI](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/bh-users.bloodhound-users.yaml)
- [User schema and role membership](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/schemas/model.user.yaml)
- [Collector-list contract](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/clients.clients.yaml)
- [Collector-detail contract](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/clients.clients.id.yaml)
- [Server permission checks](https://github.com/SpecterOps/BloodHound/blob/main/cmd/api/src/api/v2/auth/auth.go)
- [Authentication and tenant API Explorer](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api)

## Validation

```powershell
powershell -NoProfile -File .\tests\Test-Cleanup.ps1
```

Offline tests mock HTTP and prompts. They cover eligibility, timestamp boundaries/offsets, protection/exclusions, default menu navigation, roles, sorting/search, return/cancellation, export and audit events, simulation modes, revocation approval/revalidation, limits, malformed/duplicate inventories, unavailable owner lookup, ambiguous DELETE failure, and secret-free evidence. Configuration tests cover default/custom/disabled dotenv loading, precedence, explicit empty values, literal parsing, missing/malformed files, and credential-free logs. Generated artifacts remain under `tests/artifacts-*` for inspection.

Collector lookup and exact token-ID matching have been checked with read-only calls against the local test tenant. Production revocation has not been validated. This is a custom administration utility, not an official SpecterOps-supported tool.
