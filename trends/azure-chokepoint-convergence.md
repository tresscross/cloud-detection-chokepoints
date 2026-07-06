# Azure Chokepoint Convergence — the threat-intel evidence

Companion to the AWS and GCP convergence docs, for Microsoft Azure **resource / control-plane**
(Azure Activity Log). Entra ID / Azure AD *identity* is a separate log source and out of scope.
Same thesis: *TTPs evolve, chokepoints don't* — attackers converge on the same Azure Resource
Manager `operationName`s.

## Validation tiers

- **INCIDENT** — a named actor was documented performing the technique in Azure.
- **AGGREGATE** — vendor telemetry across many incidents quantifies the behavior.
- **CAPABILITY** — demonstrated feasible (research/PoC), not yet an attributed Azure incident.
- **TRANSLATABLE** — documented in AWS/GCP; the Azure equivalent is inferred.

## Actor convergence on shared Azure chokepoints

| Convergence chokepoint | Actors converging | Tier | Chokepoint IDs |
|---|---|---|---|
| RBAC role assignment for control | Storm-0501 (cloud ransomware), Scattered Spider/UNC3944 | INCIDENT | AZ-PE-01 |
| Tenant-wide elevation (elevateAccess) | Documented takeover TTP; Global-Admin abuse | CAPABILITY / TRANSLATABLE | AZ-PE-02 |
| Log/backup destruction (anti-forensics) | Storm-0501 (deletes backups, removes immutability, then encrypts) | INCIDENT | AZ-DE-01, AZ-IMP-01 |
| Storage-key / SAS credential theft | Storm-0501 (`listKeys`), leaked-key crews | INCIDENT | AZ-CA-01 |
| Disk / snapshot export for exfil | Cloud data-theft crews | TRANSLATABLE (AWS snapshot-share analogue) | AZ-EX-01 |
| VM run-command execution | Hands-on-keyboard operators | CAPABILITY | AZ-EXEC-01 |

**Storm-0501** (Microsoft MSTIC, 2025) is the anchor real-world Azure case: after reaching
Global Admin / Owner, it harvested storage keys (`listkeys`), exfiltrated, then **deleted
backups + snapshots + recovery-vault items and removed immutability/locks** before cloud-side
encryption with an attacker-controlled key — hitting AZ-PE-01, AZ-CA-01, AZ-DE-01, and
AZ-IMP-01 in sequence. Scattered Spider/UNC3944's cloud RBAC and identity abuse is well
documented across AWS/Azure/GCP; the granular Azure-`operationName` casework is thinner in
public reporting, so those mappings are marked accordingly.

## The two facts that define Azure observability (and the biggest gap)

1. **Activity Log (control-plane) is always on; resource/data-plane logs are OFF by default.**
   Role assignments, key regeneration, NSG changes, diagnostic-setting deletes, disk-export
   SAS, and run-command are all in the Activity Log. But **Key Vault secret reads, storage
   blob reads, and other data-plane access require per-resource diagnostic settings routed to
   Log Analytics** — off by default. This is the direct analogue of the AWS "S3 GetObject not
   ingested" and GCP "Data Access off by default" gaps. Blocked chokepoints: AZ-CA-03 (Key
   Vault secret read), AZ-EX-02 (bulk blob read).

2. **`roleAssignments/write` doesn't cleanly log the granted role/principal.** The Activity Log
   records the caller's *authorizing* role (`identity.authorization.evidence.role`), the target
   resource GUID, and the caller — but the assigned role/principal live in the (often unlogged)
   request body. So "Owner granted to a new principal" needs request-body inspection; the
   base rule fires on all role assignments.

### Other field caveats
- **`callerIpAddress`** can be an Azure-internal / service address for platform-initiated ops.
- **Activity Log subscription coverage may be partial** — confirm every subscription forwards
  its Activity Log to the SIEM (low overall volume can mean incomplete coverage, not low risk).
- **MITRE v19 (2026)** moved T1562 to tactic TA0112 — re-map before hard-coding.

## Where the invariants land

Per-entry `operationName`, log class, actors, and tier are in
[`../chokepoints/azure/`](../chokepoints/azure/) (14 entries across 5 tactics). The
buildable-vs-blocked split is in
[`../coverage/observability-matrix.md`](../coverage/observability-matrix.md).

Source note: `operationName`s were validated against live Azure Activity Log data; Storm-0501
detail from Microsoft Threat Intelligence (2025-08-27).
