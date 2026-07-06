# Observability matrix

Framework **Q5 — "can we observe it?"** — one section per cloud (AWS CloudTrail · GCP Cloud
Audit · Azure Activity Log). For each chokepoint: the operation
(`eventName` / `methodName` / `operationName`), its log class, whether it is **logged by
default**, and generic tuning notes.

This is a **generic** reference — it describes each cloud's *default* logging behavior, not any
one environment. Your real answer to Q5 depends on your logging configuration and SIEM parser;
always confirm volumes with a live query before shipping.

**The recurring theme across all three clouds:** control-plane *write* operations are logged by
default; *read / data-plane* operations are **not** (AWS S3 `GetObject`, GCP Data Access logs,
Azure resource diagnostics). Those chokepoints are `Default-logged? = No` until you enable the
relevant read logging.

Columns: **Default-logged?** = `Yes` (in default-on logging) · `No` (read/data-plane, off by
default) · `Yes*` (logged, but the discriminating detail is in the request body, which may not
be captured). **Notes** are generic tuning guidance — allowlists/thresholds must be built from
*your own* baseline, not assumed.

---

## AWS — CloudTrail

| Chokepoint | Tactic | Operation(s) | Log class | Default-logged? | Notes (generic) |
|---|---|---|---|---|---|
| console-login-anomaly | initial-access | `ConsoleLogin` | Management (AwsConsoleSignIn) | Yes¹ | ¹Requires the mgmt/org trail to be forwarded. SSO logins show `MFAUsed=No` (MFA at IdP) — scope the MFA branch to non-SSO IAM users. |
| iam-create-policy-version | privilege-escalation | `CreatePolicyVersion` | Management | Yes | Wildcard action + `setAsDefault` are in `requestParameters` — confirm your parser exposes it. |
| iam-inline-policy-self-escalation | privilege-escalation | `PutRolePolicy`, `PutUserPolicy` | Management | Yes | Wildcard action is in the inline policy document. |
| iam-privileged-policy-attach | privilege-escalation | `AttachUserPolicy`, `AttachRolePolicy` | Management | Yes | Match privileged managed-policy ARNs; exclude service-linked roles + the quarantine policy. |
| iam-role-trust-external-principal | persistence | `UpdateAssumeRolePolicy`, `CreateRole` | Management | Yes | Extract the external account from the trust document **only** (not the whole event). |
| iam-federation-idp-created | persistence | `Create/Update SAMLProvider`/`OIDCProvider` | Management | Yes | Near-zero base rate; exclude the SSO service-linked role. |
| iam-enumeration-burst | discovery | `ListUsers`/`ListRoles`/`GetAccountAuthorizationDetails`/… | Management | Yes | Count distinct enum ops per principal/window; allowlist scanner + service-linked roles. |
| secrets-manager-mass-read | credential-access | `GetSecretValue` | Management | Yes | Service execution roles read secrets heavily — scope to human/unexpected principals. |
| kms-key-sabotage | defense-evasion | `DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy` | Management | Yes | Exclude `GenerateDataKey`/`Decrypt` plumbing + service-invoked calls. |
| cloudtrail-config-tampering | defense-evasion | `StopLogging`, `DeleteTrail`, `StopConfigurationRecorder`, … | Management | Yes | Near-zero base rate; any occurrence is review-worthy. |
| sts-cross-account-new-principal | lateral-movement | `AssumeRole` | Management | Yes | Only with a narrowing invariant (new/external caller). Never a bare match. |
| eventbridge-cross-account-target | persistence | `PutTargets`, `PutRule` | Management | Yes | Same-account targets are common in event-driven apps — scope to cross-account targets. |
| ebs-snapshot-ami-shared-external | exfiltration | `ModifySnapshotAttribute`, `ModifyImageAttribute` | Management | Yes | Match the `.add` permission path (not `.remove`); allowlist scanning/backup vendor accounts. |
| s3-cross-account-replication | exfiltration | `PutBucketReplication` | Management | Yes | Rare operation; alert on external destinations. |
| s3-made-public | exfiltration | `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock` | Management | Yes | Public-principal / PAB-removal in `requestParameters`. |
| ses-sending-identity-abuse | impact | `VerifyDomainIdentity`, `UpdateAccountSendingEnabled`, … | Management | Yes | State-changing SES verbs are rare; the sending leg (SendEmail) is data-plane. |
| resource-hijack-cryptomining | impact | `RunInstances` | Management | Yes | Large/GPU instance heuristics + PassRole; scope to unusual actor/burst. |
| **s3-bulk-object-read** | exfiltration | `GetObject` | **Data** | **No** | S3 read data events are off by default — enable data-event logging to unblock (T1530). |

## GCP — Cloud Audit Logs

Admin Activity + System Event logs are always on; **Data Access logs are OFF by default** (only
BigQuery reads are on) — the GCP analogue of the S3 `GetObject` gap.

| Chokepoint | Tactic | Operation(s) | Log class | Default-logged? | Notes (generic) |
|---|---|---|---|---|---|
| service-account-key-created | credential-access | `CreateServiceAccountKey` | Admin Activity | Yes | Scope to human/federated creators; automation SAs mint keys routinely. |
| service-account-created | persistence | `CreateServiceAccount` | Admin Activity | Yes | Pair with key/role follow-on for the full backdoor chain. |
| setiampolicy-privileged-grant | privilege-escalation | `SetIamPolicy` | Admin Activity | Yes* | A policy always *contains* privileged roles — match the **ADD `bindingDelta`**; IaC/automation grant roles routinely, so allowlist automation principals. |
| service-account-tokencreator-grant | privilege-escalation | `SetIAMPolicy` (on SA) | Admin Activity | Yes* | Match the ADD delta granting `tokenCreator`/`serviceAccountUser`; same delta/allowlist caveat. |
| privileged-service-account-attach | privilege-escalation | host create event (compute/functions/run/DM/build) | Admin Activity | Yes | Composite — `actAs` has no event of its own; inspect the attached SA on the create event. |
| actas-bypass-deployment-agent | privilege-escalation | `CloudBuild.CreateBuild`/`CreateBuildTrigger` | Admin Activity | Yes | Cloud Build is developer-facing, so "a human built" is noisy alone — narrow via build config (reads metadata server / provisions IAM). |
| logging-sink-deleted-or-disabled | defense-evasion | `ConfigServiceV2.DeleteSink`/`UpdateSink`(disabled) | Admin Activity | Yes | Near-zero base rate; anti-forensics. |
| log-bucket-deleted-or-retention-reduced | defense-evasion | `ConfigServiceV2.DeleteBucket`/`UpdateBucket` | Admin Activity | Yes | Delete is unambiguous; retention-reduction detail is in the request. |
| firewall-opened-to-world | defense-evasion | `compute.firewalls.insert`/`patch` | Admin Activity | Yes | Match `0.0.0.0/0`; exclude the GKE control-plane robot SA (manages world-open rules by design). |
| cryptomining-compute-hijack | impact | `compute.instances.insert` | Admin Activity | Yes | Burst / GPU machine-type / multi-zone heuristics. |
| gcs-bucket-made-public | impact | `storage.setIamPermissions`/`SetIamPolicy` | Admin Activity | Yes | ADD delta binding `allUsers`/`allAuthenticatedUsers`. |
| workload-identity-federation-added | persistence | `CreateWorkloadIdentityPool(Provider)` | Admin Activity | Yes | Near-zero; a new external IdP trust is durable persistence. |
| custom-role-privilege-add / org-policy | privilege-escalation | `UpdateRole` / `SetOrgPolicy` | Admin Activity | Yes | Inspect the permission/constraint delta. |
| **sa-impersonation-token** | credential-access | `GenerateAccessToken`/`SignBlob`/`SignJwt` | **Data Access** | **No** | Enable `DATA_READ` on `iamcredentials`. |
| **secret-manager-access** | credential-access | `AccessSecretVersion` | **Data Access** | **No** | Enable `DATA_READ` on `secretmanager`. |
| **recon** | discovery | `testIamPermissions`/`getIamPolicy`/Cloud Asset `SearchAll*` | **Data Access** | **No** | Enable `ADMIN_READ`/`DATA_READ` on resourcemanager/iam/cloudasset. |
| **bulk-object-read** | exfiltration | `storage.objects.get` | **Data Access** | **No** | Enable `DATA_READ` on `storage` (T1530). |

## Azure — Activity Log

Activity Log (control-plane) is always on; **resource/data-plane logs are OFF by default**
(per-resource diagnostic settings → Log Analytics) — the Azure analogue of the same gap.

| Chokepoint | Tactic | Operation(s) | Log class | Default-logged? | Notes (generic) |
|---|---|---|---|---|---|
| role-assignment-created | privilege-escalation | `AUTHORIZATION/ROLEASSIGNMENTS/WRITE` | Activity Log | Yes* | The *granted* role/principal are in the (often unlogged) request body; the log's `evidence.role` is the caller's authorizing role. |
| elevate-access-all-subscriptions | privilege-escalation | `AUTHORIZATION/ELEVATEACCESS/ACTION` | Activity Log | Yes | Near-zero base rate; tenant-wide takeover. |
| custom-role-definition-created | privilege-escalation | `AUTHORIZATION/ROLEDEFINITIONS/WRITE` | Activity Log | Yes | Flag custom roles that include `Authorization/*` or `*/write`. |
| storage-account-key-regenerated | credential-access | `STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION` | Activity Log | Yes | `listKeys`/`listAccountSas` are routine — scope to unexpected principals. |
| key-vault-access-policy-write | credential-access | `KEYVAULT/VAULTS/WRITE` (accessPolicies) | Activity Log | Yes* | Access-policy change is visible; the secret *reads* it enables are data-plane. |
| diagnostic-settings-deleted | defense-evasion | `INSIGHTS/DIAGNOSTICSETTINGS/DELETE` | Activity Log | Yes | Near-zero base rate; anti-forensics. |
| nsg-rule-opened-to-internet | defense-evasion | `NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` | Activity Log | Yes* | The `0.0.0.0/0` source + port live in the request body — collect and triage. |
| defender-for-cloud-disabled | defense-evasion | `SECURITY/PRICINGS/WRITE`, `…/AUTOPROVISIONINGSETTINGS/WRITE` | Activity Log | Yes | Downgrade to Free / auto-provision off = reduced coverage. |
| vm-run-command | execution | `COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` (+ `RUNCOMMANDS/WRITE`) | Activity Log | Yes | Near-zero base rate; RCE via ARM. |
| app-service-kudu-command | execution | `WEB/SITES/EXTENSIONS/COMMAND/ACTION`, `…/HOST/LISTKEYS/ACTION` | Activity Log | Yes | CI/CD deploys hit these routinely — allowlist deploy principals. |
| managed-disk-exported-sas | exfiltration | `COMPUTE/DISKS/BEGINGETACCESS/ACTION` | Activity Log | Yes | Backup/DR tooling uses `restorePoints/retrieveSasUris` — allowlist it; `beginGetAccess` by a non-backup principal is the signal. |
| backup-recovery-destruction | impact | recovery-vault/snapshot `DELETE`, `AUTHORIZATION/LOCKS/DELETE` | Activity Log | Yes | Burst / non-backup principal deleting recovery items or removing locks. |
| **key-vault-secret-read** | credential-access | `SecretGet`/`KeyGet` | **data-plane** | **No** | Enable Key Vault AuditEvent diagnostic logging → Log Analytics. |
| **storage-bulk-blob-read** | exfiltration | `GetBlob` | **data-plane** | **No** | Enable Storage `StorageRead` diagnostic logging (T1530). |

---

## Cross-cloud caveats (verify before relying on any detection)

1. **Read/data-plane logging is off by default on every cloud** (the `No` rows). Enabling it is
   the highest-leverage coverage improvement — and the biggest cost decision (scope to
   crown-jewel resources; reads are the expensive volume).
2. **The discriminating signal often lives in the request body / policy document** (`Yes*` rows):
   AWS `requestParameters`, GCP `bindingDeltas`, Azure request body. Confirm your parser exposes
   it — some flatten it to fields, some leave it only in the raw event.
3. **"Policy contains" vs "delta added"** (IAM grants, all clouds): a policy always contains
   privileged roles, so match the **ADD delta**, not the presence of the role. IaC/automation
   legitimately grant roles, so allowlist automation principals from your own baseline.
4. **Field-to-field comparisons** (`callerAccount ≠ resourceAccount`, `targetAccount ≠ ruleAccount`):
   many query languages compare a field to the *literal string* of the other field name unless
   you use an explicit comparison function. Validate the result count on real data.
5. **Caller-IP redaction:** cloud-internal / service-to-service calls show internal or service
   addresses (AWS service names, GCP `private`/`gce-internal-ip`, Azure internal), so IP-based
   geo/anomaly logic can't see intra-cloud moves.
