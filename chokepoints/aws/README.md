# AWS control-plane detection chokepoints

Chokepoint entries for Amazon Web Services, organized by MITRE ATT&CK tactic, following the
upstream schema. A chokepoint is an **invariant** control-plane prerequisite an attacker cannot
avoid — anchored to **CloudTrail `eventName`** values, not tool signatures.

> **Scope:** AWS **management / control-plane** (CloudTrail management events). Console-login and
> federated identity that flow through a separate IdP are treated as their own source.

## Files

Entries are **one file per chokepoint**, stored under tactic subfolders as
`chokepoints/aws/<tactic>/<slug>.yml`, following the unified
[`templates/chokepoint-template.yml`](../../templates/chokepoint-template.yml) schema.

| Tactic subfolder | Tactic |
|---|---|
| `initial-access/` | Initial Access (TA0001) |
| `credential-access/` | Credential Access (TA0006) |
| `discovery/` | Discovery (TA0007) |
| `privilege-escalation/` | Privilege Escalation (TA0004) |
| `persistence/` | Persistence (TA0003) |
| `defense-evasion/` | Defense Evasion (TA0005) |
| `lateral-movement/` | Lateral Movement (TA0008) |
| `exfiltration/` | Exfiltration (TA0010) |
| `impact/` | Impact (TA0040) |

## Two facts that shape AWS chokepoints

1. **Management events are always on; S3 (and other) data events are OFF by default.** Bulk-read
   exfil (`GetObject`) is unbuildable from CloudTrail until data-event logging is enabled — the
   AWS analogue of the GCP Data-Access / Azure data-plane gap. Such entries are `INGEST_GAP`.
2. **The discriminating signal often lives in `requestParameters` / the policy document.** Confirm
   your parser exposes it (some flatten it to fields, some leave it only in the raw event), and
   remember field-to-field comparisons (`callerAccount ≠ resourceAccount`) need an explicit
   comparison function, not a bare `!=`.

## Field conventions

Entries reference CloudTrail fields: `eventName`, `requestParameters.*`, `userIdentity.type`,
`userIdentity.sessionContext.sessionIssuer.userName` (group on this — not the per-session ARN),
`sourceIPAddress`. Example account IDs are placeholders (`123456789012` / `210987654321`).
