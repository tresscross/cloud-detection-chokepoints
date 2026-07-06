# Cloud Detection Chokepoints

> **TTPs evolve. Chokepoints don't.**

A catalog of **invariant control-plane prerequisites** for cloud attack techniques — the
mandatory API calls an attacker *cannot avoid* regardless of tooling — and the detections that
anchor to them. Covers **AWS (CloudTrail)**, **GCP (Cloud Audit Logs)**, and **Azure (Activity
Log)**: **58 chokepoints across 3 clouds and 10 ATT&CK tactics.**

Applies the [iimp0ster/detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints)
methodology (built for EDR/endpoint) to **cloud control-plane logs** — AWS CloudTrail
`eventName`s, GCP Cloud Audit `methodName`s, Azure Activity Log `operationName`s.

---

## Why this exists

Threat-actor tooling rotates constantly; the underlying technical requirements don't. Kaspersky
analysed eight major ransomware operations and found they converged on the same core kill chain
— the tools differed, the requirements didn't. The same holds in the cloud: ransomware crews,
access brokers, cryptominers, and hands-on-keyboard operators all funnel through the same handful
of control-plane APIs — `CreatePolicyVersion`, `SetIamPolicy`, `roleAssignments/write`,
`CreateServiceAccountKey`, `ModifySnapshotAttribute`, `StopLogging`, `DeleteSink`,
`diagnosticSettings/delete` — because the platform gives them no other path to the outcome.

A rule keyed on an offensive tool's signature dies when the tool recompiles. A rule keyed on the
invariant — *"a new default IAM policy version granting `Action:*`"* — fires no matter what wrote
it. See [`trends/`](trends/) for the campaign-by-campaign evidence.

## Chokepoint index

Every entry lives at `chokepoints/<cloud>/<tactic>/<slug>.yml` and carries a `validation_tier`
(**INCIDENT** = named actor observed in this cloud · **AGGREGATE** = prevalent in vendor
telemetry · **CAPABILITY** = feasible/PoC, not yet an attributed incident · **TRANSLATABLE** =
seen in another cloud). **`[blind]`** = observable only after read/data-plane logging is enabled
(see [Observability](#observability--the-read-log-gap)).

### AWS — CloudTrail (15)

| Chokepoint | Tactic | Priority | Tier |
|---|---|---|---|
| [Secrets Manager read by a human or unknown principal](chokepoints/aws/credential-access/secrets-manager-mass-read.yml) | credential-access | HIGH | INCIDENT |
| [CloudTrail / Config / FlowLog tampering](chokepoints/aws/defense-evasion/cloudtrail-config-tampering.yml) | defense-evasion | HIGH | INCIDENT |
| [KMS key sabotage or public key policy](chokepoints/aws/defense-evasion/kms-key-sabotage.yml) | defense-evasion | HIGH | CAPABILITY |
| [IAM / account enumeration burst](chokepoints/aws/discovery/iam-enumeration-burst.yml) | discovery | MEDIUM | INCIDENT |
| [EBS snapshot / AMI shared to an external account](chokepoints/aws/exfiltration/ebs-snapshot-ami-shared-external.yml) | exfiltration | HIGH | AGGREGATE |
| [S3 ransomware via SSE-C encryption-in-place](chokepoints/aws/impact/s3-sse-c-ransomware.yml) | impact | HIGH | INCIDENT |
| [SES sending / identity abuse](chokepoints/aws/impact/ses-sending-identity-abuse.yml) | impact | MEDIUM | INCIDENT |
| [Console sign-in anomaly (MFA bypass / foreign geo)](chokepoints/aws/initial-access/console-login-anomaly.yml) | initial-access | HIGH | AGGREGATE |
| [Cross-account AssumeRole from a new external principal](chokepoints/aws/lateral-movement/sts-cross-account-new-principal.yml) | lateral-movement | MEDIUM | AGGREGATE |
| [Federation / identity-provider backdoor](chokepoints/aws/persistence/iam-federation-idp-created.yml) | persistence | HIGH | CAPABILITY |
| [Role trust policy grants an external principal](chokepoints/aws/persistence/iam-role-trust-external-principal.yml) | persistence | HIGH | INCIDENT |
| [EventBridge rule wired to a cross-account target](chokepoints/aws/persistence/eventbridge-cross-account-target.yml) | persistence | MEDIUM | CAPABILITY |
| [IAM policy-version self-escalation](chokepoints/aws/privilege-escalation/iam-create-policy-version.yml) | privilege-escalation | CRITICAL | AGGREGATE |
| [Inline-policy self-escalation](chokepoints/aws/privilege-escalation/iam-inline-policy-self-escalation.yml) | privilege-escalation | CRITICAL | AGGREGATE |
| [Privileged managed-policy attached to a user or role](chokepoints/aws/privilege-escalation/iam-privileged-policy-attach.yml) | privilege-escalation | HIGH | INCIDENT |

### GCP — Cloud Audit Logs (29)

| Chokepoint | Tactic | Priority | Tier |
|---|---|---|---|
| [Service-account impersonation — access/OIDC token minting & signing](chokepoints/gcp/credential-access/service-account-impersonation-token.yml) | credential-access | CRITICAL | CAPABILITY `[blind]` |
| [Service-account key creation (long-lived credential minting)](chokepoints/gcp/credential-access/service-account-key-created.yml) | credential-access | CRITICAL | INCIDENT |
| [Compute instance metadata token theft (SA token from 169.254.169.254)](chokepoints/gcp/credential-access/instance-metadata-token-theft.yml) | credential-access | HIGH | CAPABILITY `[blind]` |
| [Secret Manager secret access](chokepoints/gcp/credential-access/secret-manager-access.yml) | credential-access | HIGH | CAPABILITY `[blind]` |
| [Logging sink deletion or disable](chokepoints/gcp/defense-evasion/logging-sink-deleted-or-disabled.yml) | defense-evasion | CRITICAL | AGGREGATE |
| [Audit logging disabled via IAM auditConfig change](chokepoints/gcp/defense-evasion/audit-logging-disabled-auditconfig.yml) | defense-evasion | HIGH | CAPABILITY |
| [Log bucket deletion / retention reduction](chokepoints/gcp/defense-evasion/log-bucket-deleted-or-retention-reduced.yml) | defense-evasion | HIGH | CAPABILITY |
| [Firewall opened to the world](chokepoints/gcp/defense-evasion/firewall-opened-to-world.yml) | defense-evasion | MEDIUM | CAPABILITY |
| [Telemetry disabled — VPC Flow Logs / DNS logging / project detach](chokepoints/gcp/defense-evasion/network-telemetry-disabled.yml) | defense-evasion | MEDIUM | CAPABILITY |
| [IAM permission brute-forcing (testIamPermissions / queryTestablePermissions)](chokepoints/gcp/discovery/iam-permission-bruteforce.yml) | discovery | HIGH | CAPABILITY `[blind]` |
| [Org-wide asset enumeration via Cloud Asset Inventory](chokepoints/gcp/discovery/cloud-asset-inventory-enumeration.yml) | discovery | MEDIUM | CAPABILITY `[blind]` |
| [Resource enumeration (instances/buckets/service-accounts list)](chokepoints/gcp/discovery/resource-enumeration.yml) | discovery | MEDIUM | CAPABILITY `[blind]` |
| [Bulk object read / data exfiltration from Cloud Storage](chokepoints/gcp/exfiltration/gcs-bulk-object-read.yml) | exfiltration | HIGH | CAPABILITY `[blind]` |
| [Cross-project data transfer via resource IAM sharing](chokepoints/gcp/exfiltration/cross-project-resource-share.yml) | exfiltration | HIGH | INCIDENT |
| [Data destruction / ransomware (mass delete or client-side re-encrypt)](chokepoints/gcp/impact/gcs-data-destruction-ransomware.yml) | impact | HIGH | CAPABILITY |
| [GCS bucket / object made public](chokepoints/gcp/impact/gcs-bucket-made-public.yml) | impact | HIGH | CAPABILITY |
| [Resource hijacking — compute spun up for cryptomining](chokepoints/gcp/impact/cryptomining-compute-hijack.yml) | impact | HIGH | INCIDENT |
| [Valid cloud account / stolen credential used against the control plane](chokepoints/gcp/initial-access/valid-account-control-plane.yml) | initial-access | CRITICAL | INCIDENT |
| [New service account created and keyed (durable foothold)](chokepoints/gcp/persistence/service-account-created-and-keyed.yml) | persistence | HIGH | CAPABILITY |
| [Workload Identity Federation / external IdP provider added](chokepoints/gcp/persistence/workload-identity-federation-added.yml) | persistence | HIGH | TRANSLATABLE |
| [SSH key added to project/instance metadata (lateral persistence)](chokepoints/gcp/persistence/ssh-key-added-to-metadata.yml) | persistence | MEDIUM | CAPABILITY |
| [Serverless / scheduled backdoor (public function or scheduled job)](chokepoints/gcp/persistence/serverless-scheduled-backdoor.yml) | persistence | MEDIUM | CAPABILITY |
| [Attach a privileged service account to a new resource (actAs / PassRole-analog)](chokepoints/gcp/privilege-escalation/privileged-service-account-attach.yml) | privilege-escalation | CRITICAL | CAPABILITY |
| [Backdoor a service account via its IAM policy (grant TokenCreator)](chokepoints/gcp/privilege-escalation/service-account-tokencreator-grant.yml) | privilege-escalation | CRITICAL | CAPABILITY |
| [setIamPolicy self-grant / external grant at project / folder / org](chokepoints/gcp/privilege-escalation/setiampolicy-privileged-grant.yml) | privilege-escalation | CRITICAL | INCIDENT |
| [Compute instance created with startup-script + attached SA](chokepoints/gcp/privilege-escalation/instance-startup-script-attached-sa.yml) | privilege-escalation | HIGH | CAPABILITY |
| [Org policy constraint weakened to enable other primitives](chokepoints/gcp/privilege-escalation/org-policy-constraint-weakened.yml) | privilege-escalation | HIGH | CAPABILITY |
| [actAs-bypass via Deployment Manager / Cloud Build default agent](chokepoints/gcp/privilege-escalation/actas-bypass-deployment-agent.yml) | privilege-escalation | HIGH | CAPABILITY |
| [Custom role updated to add privileges](chokepoints/gcp/privilege-escalation/custom-role-privilege-add.yml) | privilege-escalation | MEDIUM | CAPABILITY |

### Azure — Activity Log (14)

| Chokepoint | Tactic | Priority | Tier |
|---|---|---|---|
| [Key Vault access policy / vault write](chokepoints/azure/credential-access/key-vault-access-policy-write.yml) | credential-access | HIGH | CAPABILITY |
| [Key Vault secret read](chokepoints/azure/credential-access/key-vault-secret-read.yml) | credential-access | HIGH | CAPABILITY `[blind]` |
| [Storage account key regenerated](chokepoints/azure/credential-access/storage-account-key-regenerated.yml) | credential-access | MEDIUM | CAPABILITY |
| [Diagnostic settings deleted](chokepoints/azure/defense-evasion/diagnostic-settings-deleted.yml) | defense-evasion | HIGH | CAPABILITY |
| [NSG rule opened to the internet](chokepoints/azure/defense-evasion/nsg-rule-opened-to-internet.yml) | defense-evasion | HIGH | CAPABILITY |
| [Microsoft Defender for Cloud / auto-provisioning disabled](chokepoints/azure/defense-evasion/defender-for-cloud-disabled.yml) | defense-evasion | MEDIUM | CAPABILITY |
| [VM run-command execution](chokepoints/azure/execution/vm-run-command.yml) | execution | HIGH | CAPABILITY |
| [App Service (Kudu) command / function key access](chokepoints/azure/execution/app-service-kudu-command.yml) | execution | MEDIUM | CAPABILITY |
| [Managed disk exported via SAS](chokepoints/azure/exfiltration/managed-disk-exported-sas.yml) | exfiltration | HIGH | CAPABILITY |
| [Storage bulk blob read (data exfiltration)](chokepoints/azure/exfiltration/storage-bulk-blob-read.yml) | exfiltration | HIGH | CAPABILITY `[blind]` |
| [Backup / recovery destruction](chokepoints/azure/impact/backup-recovery-destruction.yml) | impact | HIGH | INCIDENT |
| [Elevate access to all subscriptions (tenant-wide)](chokepoints/azure/privilege-escalation/elevate-access-all-subscriptions.yml) | privilege-escalation | CRITICAL | CAPABILITY |
| [RBAC role assignment created](chokepoints/azure/privilege-escalation/role-assignment-created.yml) | privilege-escalation | HIGH | INCIDENT |
| [Custom role definition created or modified](chokepoints/azure/privilege-escalation/custom-role-definition-created.yml) | privilege-escalation | MEDIUM | CAPABILITY |

## Attack chains

Different crews, different tools, the same control-plane path. See
[`attack-chains/`](attack-chains/) for the worked cloud-account-takeover chain (initial access →
enumeration → credential access → escalation → persistence → defense evasion → exfiltration →
impact), each stage annotated with the chokepoint that fires. The highest-leverage five sit on
nearly every playbook: enumeration burst, the three privilege-escalation primitives, and the
role/trust-policy persistence move.

## The framework

Six questions per chokepoint (adapted from the upstream methodology):

1. What is the technique, technically?
2. What preconditions enable it?
3. What does the attacker control? (user agent, IP, tool, timing, names)
4. **What can't the attacker control?** ← the chokepoint (the mandatory operation + narrowing invariant)
5. Can we observe it? (is the operation in the audit log, and does the discriminating field survive?)
6. What are all the variations? (every API path to the same outcome)

**Qualification gate:** *If the attacker switches tools tomorrow, does the detection still fire?*
If it keys on a tool/UA/IP/session name, it isn't a chokepoint — move the anchor to the invariant.

## Detection maturity model

Every chokepoint carries detection logic at three tiers:

| Tier | FP rate | Purpose |
|---|---|---|
| **Research** | high | Establish baseline visibility — every occurrence, minimal filter. |
| **Hunt** | medium | Add the narrowing invariant + grouping. |
| **Analyst** | low | Production alert — tightest invariant + allowlists built from *your own* baseline; carries severity. |

Portable [Sigma](https://github.com/SigmaHQ/sigma) rules for the buildable chokepoints are in
[`sigma-rules/`](sigma-rules/) (`<cloud>_<slug>.yml`).

## Observability — the read-log gap

The recurring cloud truth: **write/control-plane operations are logged by default; read/data-plane
operations are not.** Each cloud has the same gap, and it blocks the same chokepoint cluster
(secret reads, object-read exfil, impersonation, recon):

| Cloud | Always on | Off by default (`[blind]`) |
|---|---|---|
| AWS | CloudTrail management events | S3 `GetObject` / data events |
| GCP | Admin Activity + System Event | Data Access logs (secretmanager, storage, iamcredentials, …) |
| Azure | Activity Log (control-plane) | Resource/data-plane diagnostic logs (Key Vault, Storage) |

`[blind]` entries in the index above are `observability.status: INGEST_GAP` — real chokepoints,
detectable only after the relevant read-logging is enabled. The full event → invariant →
buildability reference is [`coverage/observability-matrix.md`](coverage/observability-matrix.md).

## Trends (threat-intel backing)

[`trends/`](trends/) maps real, publicly-documented campaigns to the chokepoints they were forced
to touch — one convergence doc per cloud (AWS, GCP, Azure), each with a validation-tier table and
aggregate stats (CrowdStrike, Datadog, Unit 42, Sysdig, Mandiant, Google Threat Horizons,
Microsoft MSTIC). We label honestly: 14 chokepoints are **INCIDENT**-validated, the rest are
**AGGREGATE**/**CAPABILITY**/**TRANSLATABLE** — and the doc says which, and why.

## Repository structure

```
chokepoints/<cloud>/<tactic>/<slug>.yml   One file per chokepoint (aws | gcp | azure).
sigma-rules/                              Portable Sigma detections, <cloud>_<slug>.yml.
trends/                                   Threat-intel convergence evidence, one doc per cloud.
attack-chains/                            Kill-chain docs mapping stages to chokepoints.
coverage/observability-matrix.md          Event → invariant → buildability, per cloud.
emulation/                                Safe, lab-only validation commands.
schema/                                   Entry schema + valid enum values.
templates/                                chokepoint-template.yml, quick-add.md, EXAMPLE-WORKFLOW.md.
```

## How to use

- **Detection engineers:** lift the Sigma rules or the invariant analysis; adapt the Analyst-tier
  allowlists to your environment. **Don't ship the Analyst tier without baselining against your own
  data** — allowlists and thresholds here are placeholders.
- **Threat hunters:** the Research-tier logic is your starting hunt; [`attack-chains/`](attack-chains/)
  shows which chokepoints to prioritise.
- **Red teamers:** [`emulation/`](emulation/) has safe, lab-only commands to generate each
  chokepoint's telemetry.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`schema/chokepoint-schema.md`](schema/chokepoint-schema.md),
and [`templates/`](templates/). New entries must pass the qualification gate, cite the observable
operation(s), and set a `validation_tier`. Use `templates/quick-add.md` for a tool variant on an
existing chokepoint.

## License & acknowledgements

[MIT](LICENSE). Methodology and structure adapted from
[iimp0ster/detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints).
