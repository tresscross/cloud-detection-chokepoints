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
