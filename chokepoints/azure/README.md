# Azure control-plane detection chokepoints

Chokepoint entries for Microsoft Azure, organized by MITRE ATT&CK tactic, following the
upstream schema. A chokepoint is an **invariant** control-plane prerequisite an attacker
cannot avoid — anchored to **Azure Activity Log `operationName`** values (the Azure Resource
Manager operation), not tool signatures.

> **Scope:** Azure **resource / control-plane** (Azure Activity Log). Entra ID / Azure AD
> identity (sign-ins, OAuth, conditional access) is a *separate* log source and is out of
> scope here — treat it like AWS console-login vs CloudTrail.

## Files

| File | Tactic |
|---|---|
| `privilege-escalation.yml` | Privilege Escalation (TA0004) |
| `credential-access.yml` | Credential Access (TA0006) |
| `defense-evasion.yml` | Defense Evasion (TA0005) |
| `execution.yml` | Execution (TA0002) |
| `exfiltration.yml` | Exfiltration / Impact (TA0010 / TA0040) |

## The two facts that shape every Azure chokepoint

1. **Activity Log (control-plane) is always on; resource/data-plane logs are OFF by default.**
   Role assignments, resource writes, key regeneration, NSG changes, diagnostic-setting
   deletes, disk-export SAS, and run-command all land in the **Activity Log** (free, always
   on). But **Key Vault secret reads, storage blob reads, and other data-plane access require
   per-resource diagnostic settings routed to Log Analytics** and are off by default — the
   direct analogue of the AWS "S3 GetObject not ingested" and GCP "Data Access off" gaps.
2. **`roleAssignments/write` doesn't cleanly log the *granted* role/principal.** The Activity
   Log records the caller's *authorizing* role (`identity.authorization.evidence.role`), the
   target resource GUID, and the caller — but the role/principal being assigned live in the
   (often unlogged) request body. Narrowing "Owner granted to X" needs request-body inspection.

## Field conventions

Entries reference these Azure Activity Log fields:
`operationName` (the ARM operation, e.g. `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`),
`caller` / `identity.claims.name` (actor; `idtyp` = `user` vs `app`),
`callerIpAddress`, `resultType`, `category` (`Administrative`/`Security`/`Policy`),
and the target resource id. Example account IDs/resources here are placeholders.
