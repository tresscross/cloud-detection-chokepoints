# GCP control-plane detection chokepoints

Chokepoint entries for Google Cloud, organized by MITRE ATT&CK tactic, following the unified
repo schema (`../../schema/chokepoint-schema.md`; worked example in
`../../templates/chokepoint-template.yml`). A chokepoint is an **invariant** control-plane
prerequisite an attacker cannot avoid — anchored to GCP Cloud Audit Log
`protoPayload.methodName` values, not tool signatures.

## Layout

Entries are now **one file per chokepoint**, stored under a per-tactic subfolder:

```
chokepoints/gcp/<tactic>/<slug>.yml
```

`<tactic>` is the MITRE ATT&CK tactic in kebab-case (`initial-access`, `credential-access`,
`discovery`, `privilege-escalation`, `persistence`, `defense-evasion`, `exfiltration`,
`impact`). Each file's `id` is `gcp-<slug>` and matches its filename.

| Tactic subfolder | Tactic |
|---|---|
| `initial-access/` | Initial Access / Valid Accounts (TA0001) |
| `credential-access/` | Credential Access (TA0006) |
| `discovery/` | Discovery (TA0007) |
| `privilege-escalation/` | Privilege Escalation (TA0004) |
| `persistence/` | Persistence (TA0003) |
| `defense-evasion/` | Defense Evasion (TA0005) |
| `exfiltration/` | Exfiltration (TA0010) |
| `impact/` | Impact (TA0040) |

## The two facts that shape every GCP chokepoint

1. **Admin Activity vs Data Access.** Admin Activity + System Event audit logs are
   **always on and free**. **Data Access logs are OFF by default** (the sole exception is
   BigQuery data reads). Every chokepoint records which class its `methodName` lands in via
   `observability.log_class`. The Data-Access-off-by-default gap is the GCP analog of the AWS
   "S3 GetObject not ingested" gap — those entries carry `observability.status: INGEST_GAP`.

2. **`iam.serviceAccounts.actAs` has no audit event of its own.** It is a permission check
   enforced at resource-creation time. Impersonation-via-attach is only observable through the
   *host* resource-creation event (`instances.insert`, `CreateFunction`, `CreateService`,
   `deployments.insert`, `CreateBuild`, `CreateJob`) with the attached service account
   inspected.

## Field conventions

Entries reference these Cloud Audit Log fields (verified against the canonical
`audit_log.proto`):
`protoPayload.methodName`, `protoPayload.serviceName`,
`protoPayload.authenticationInfo.principalEmail`,
`protoPayload.authorizationInfo[].permission|.granted`,
`protoPayload.resourceName`, `protoPayload.requestMetadata.callerIp`,
`protoPayload.requestMetadata.callerSuppliedUserAgent`,
`protoPayload.request.*` / `protoPayload.response.*`, and
`protoPayload.serviceData.policyDelta.bindingDeltas[]` (⚠ `serviceData` is deprecated and
frequently dropped from exported logs — prefer `protoPayload.metadata` where available).

In NG-SIEM, scope with `#Vendor=gcp` inside the shared `#repo=<csp_events_repo>`.

## Field-accuracy caveat

Google's official audit-logging doc pages were not directly fetchable during research
(egress 403), so a few fully-qualified `methodName` strings are flagged in the per-entry
`observability.notes` as `VALIDATE`. Confirm those against the live
`cloud.google.com/*/docs/*/audit-logging` pages before shipping a rule.
