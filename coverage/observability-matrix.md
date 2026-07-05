# Observability matrix

Framework **Q5 — "can we observe it?"** — as a reference table. For each chokepoint: the
CloudTrail event(s), the event category, where the discriminating signal lives, and the
common ingestion gaps that decide whether a detection is buildable.

This is a **generic** reference. Your environment's answer to Q5 depends on your trail
configuration and your SIEM parser — always confirm with a live query.

## Event → signal → buildability

| Chokepoint | CloudTrail event(s) | Category | Signal lives in | Buildable? / notes |
|---|---|---|---|---|
| console-login-anomaly | `ConsoleLogin` | Management (AwsConsoleSignIn) | `additionalEventData.MFAUsed`, `sourceIPAddress`, `userIdentity.type` | Only if console sign-ins are forwarded (org/mgmt trail) — **confirm**. SSO shows MFAUsed=No normally. |
| iam-create-policy-version | `CreatePolicyVersion` | Management | `requestParameters.policyDocument`, `.setAsDefault` | Yes. Wildcard action is in the policy doc — confirm parser exposes `requestParameters`. |
| iam-inline-policy-self-escalation | `PutRolePolicy`, `PutUserPolicy` | Management | `requestParameters.policyDocument` | Yes. |
| iam-privileged-policy-attach | `AttachUserPolicy`, `AttachRolePolicy` | Management | `requestParameters.policyArn` | Yes. Exclude service-linked roles + quarantine policy. |
| iam-role-trust-external-principal | `UpdateAssumeRolePolicy`, `CreateRole` | Management | trust JSON (`requestParameters.policyDocument` / `.assumeRolePolicyDocument`) | Yes. Extract external account from the trust doc ONLY. |
| iam-federation-idp-created | `Create/Update SAMLProvider`, `…OIDCProvider` | Management | `eventName` (+ `requestParameters.name/.url`) | Yes. Near-zero base rate. |
| iam-enumeration-burst | `ListUsers`/`ListRoles`/`GetAccountAuthorizationDetails`/… | Management | `eventName` (distinct count per principal/window) | Yes. Allowlist scanner/service-linked roles. |
| secrets-manager-mass-read | `GetSecretValue` | Management | `userIdentity.type`, `requestParameters.secretId` | Yes. Service-role reads are high-volume baseline. |
| kms-key-sabotage | `DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy` | Management | `eventName`, `requestParameters.policy` | Yes. Exclude GenerateDataKey/Decrypt + service callers. |
| cloudtrail-config-tampering | `StopLogging`, `DeleteTrail`, `StopConfigurationRecorder`, … | Management | `eventName`, `requestParameters` | Yes. |
| sts-cross-account-new-principal | `AssumeRole` | Management | `userIdentity.accountId` vs `recipientAccountId`, `resources[].ARN` | Yes, but ONLY with a narrowing invariant (new pair / external caller). Never bare match. |
| eventbridge-cross-account-target | `PutTargets`, `PutRule` | Management | `requestParameters.targets[].arn` (target account) | Yes for the cross-account cut; same-account is high-volume. |
| ebs-snapshot-ami-shared-external | `ModifySnapshotAttribute`, `ModifyImageAttribute` | Management | `requestParameters.*Permission.add.items[].userId/.group` | Yes. Match the `.add` path, not `.remove`. |
| s3-cross-account-replication | `PutBucketReplication` | Management | destination bucket in `requestParameters` | Yes. Often zero-baseline. |
| s3-made-public | `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock` | Management | `requestParameters` (policy / ACL / PAB) | Yes. |
| ses-sending-identity-abuse | `VerifyDomainIdentity`, `UpdateAccountSendingEnabled`, … | Management | `eventName`, `requestParameters.identity/.domain` | Yes. Often zero-baseline for the write verbs. |
| **s3-bulk-object-read** | `GetObject` | **Data** | — | **Often NOT observable** — S3 data-event read logging is off by default. See gaps. |
| resource-hijack (cryptomining) | `RunInstances` | Management | instance type, `requestParameters` | Yes (large/GPU instance heuristics + PassRole). |

## Common ingestion gaps (verify before relying on a detection)

1. **S3 (and other) data events are off by default.** `GetObject` / object-level reads are
   *not* in CloudTrail unless data-event logging is explicitly enabled on the bucket/trail.
   Bulk-read exfil (T1530) is **unbuildable** from CloudTrail until you turn it on. Write
   data events (`PutObject`, `DeleteObjects`) may be partially present.
2. **Console sign-ins** require the management-account / org trail to be forwarded. If absent,
   `ConsoleLogin` detections silently never fire — confirm, don't assume.
3. **CloudTrail Insights** (anomalous API-rate events) are a separate opt-in category.
4. **`requestParameters` / `responseElements` / `additionalEventData`** are the source of
   truth for policy documents, share targets, and MFA state. **Confirm your parser exposes
   them** — some flatten them to fields, some leave them only in the raw event.
5. **Federated (`AssumeRoleWithSAML`) source IPs** are often broker/service IPs, not the
   user's real location — use `ConsoleLogin.sourceIPAddress` for geo signals.

## A note on field-to-field comparisons

Detections like `sts-cross-account-new-principal` (`callerAccount ≠ resourceAccount`) and
`eventbridge-cross-account-target` (`targetAccount ≠ ruleAccount`) require comparing two
fields. **Many query languages, given `fieldA != fieldB`, compare `fieldA` to the literal
string `"fieldB"`** and match every record. Use your platform's explicit field-comparison
function and validate the result count on real data before shipping.

---

# GCP Cloud Audit Logs — observability matrix

GCP's `protoPayload.methodName` equivalent of the AWS table above. The dividing line is the
**audit-log class**: Admin Activity + System Event are always on; **Data Access is OFF by
default** (only BigQuery reads are on) — the GCP analogue of the S3 GetObject gap.

| Chokepoint | Tactic | methodName | Log class | Buildable now? |
|---|---|---|---|---|
| SA key creation | Cred Access | `google.iam.admin.v1.CreateServiceAccountKey` | ADMIN | **YES** |
| new service account | Persistence | `google.iam.admin.v1.CreateServiceAccount` | ADMIN | **YES** |
| setIamPolicy privileged grant | Priv Esc | `SetIamPolicy` (+ ADD bindingDelta) | ADMIN | PARTIAL — needs IaC allowlist (ADD deltas dominated by automation) |
| SA impersonation backdoor | Priv Esc | `SetIAMPolicy` on SA (+ tokenCreator delta) | ADMIN | PARTIAL — same delta/allowlist caveat |
| actAs attach priv SA | Priv Esc | host create event (compute/functions/run/DM/build) | ADMIN | COMPOSITE (no actAs event of its own) |
| Cloud Build actAs-bypass | Priv Esc | `CloudBuild.CreateBuild`/`CreateBuildTrigger` | ADMIN | PARTIAL — human builds are normal; needs build-config inspection |
| logging sink delete/disable | Defense Evasion | `ConfigServiceV2.DeleteSink`/`UpdateSink`(disabled) | ADMIN | **YES** |
| log bucket delete/retention | Defense Evasion | `ConfigServiceV2.DeleteBucket`/`UpdateBucket` | ADMIN | **YES** |
| firewall open to world | Defense Evasion | `compute.firewalls.insert`/`patch` (+ 0.0.0.0/0) | ADMIN | **YES** (exclude GKE control-plane robot) |
| crypto-mining compute burst | Impact | `compute.instances.insert` (burst/GPU) | ADMIN | **YES** (burst logic) |
| GCS made public | Impact | `storage.setIamPermissions`/`SetIamPolicy` (+ allUsers) | ADMIN | **YES** |
| WIF / external IdP added | Persistence | `WorkloadIdentityPools.CreateWorkloadIdentityPool(Provider)` | ADMIN | YES |
| custom role / org policy | Priv Esc | `google.iam.admin.v1.UpdateRole` / `SetOrgPolicy` | ADMIN | YES |
| **SA impersonation (token mint)** | Cred Access | `GenerateAccessToken`/`SignBlob`/`SignJwt` | **DATA*** | **BLOCKED** — enable DATA_READ on iamcredentials |
| **Secret Manager read** | Cred Access | `AccessSecretVersion` | **DATA*** | **BLOCKED** — enable DATA_READ on secretmanager |
| **recon** | Discovery | `testIamPermissions`/`getIamPolicy`/Cloud Asset `SearchAll*` | **DATA*** | **BLOCKED** — enable ADMIN_READ/DATA_READ |
| **bulk GCS object read** | Exfiltration | `storage.objects.get` | **DATA*** | **BLOCKED** — enable DATA_READ on storage (T1530) |

## GCP-specific gaps & caveats

1. **Data Access logs OFF by default** (the `DATA*` rows) — the single biggest GCP coverage
   gap. Highest-leverage fix: enable `DATA_READ`/`ADMIN_READ` for `iamcredentials`,
   `secretmanager`, `cloudresourcemanager`, `cloudasset`, and `storage`.
2. **`SetIamPolicy` "policy contains" vs "delta added"** — a policy always contains
   `roles/owner` etc., so matching the role in the whole policy fires on every call. Match the
   **ADD `bindingDelta`**; even then privileged-role ADDs are dominated by IaC/automation, so
   an IaC-principal allowlist is required before shipping.
3. **`iam.serviceAccounts.actAs` has no methodName** — catch impersonation-via-attach through
   the host resource-create event with the attached SA inspected (GCP PassRole analogue).
4. **`serviceData` deprecated / dropped on export** — binding & auditConfig deltas may be
   unreliable in exported logs; prefer `protoPayload.metadata`; validate against a live sample.
5. **`callerIp` redaction** (`"private"`/`"gce-internal-ip"`) hides intra-Google moves;
   **`PERMISSION_DENIED`** can drop `principalEmail` for user identities.
