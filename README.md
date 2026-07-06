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
| IAM policy-version self-escalation | privilege-escalation | CRITICAL | AGGREGATE |
| Inline-policy self-escalation | privilege-escalation | CRITICAL | AGGREGATE |
| Privileged managed-policy attach | privilege-escalation | HIGH | INCIDENT |
| Role trust policy grants external principal | persistence | HIGH | INCIDENT |
| Federation / IdP backdoor | persistence | HIGH | CAPABILITY |
| EventBridge rule → cross-account target | persistence | MEDIUM | CAPABILITY |
| Secrets Manager read by human/unknown principal | credential-access | HIGH | INCIDENT |
| IAM / account enumeration burst | discovery | MEDIUM | INCIDENT |
| CloudTrail / Config / FlowLog tampering | defense-evasion | HIGH | INCIDENT |
| KMS key sabotage or public key policy | defense-evasion | HIGH | CAPABILITY |
| Cross-account AssumeRole from new external principal | lateral-movement | MEDIUM | AGGREGATE |
| Console sign-in anomaly (MFA bypass / foreign geo) | initial-access | HIGH | AGGREGATE |
| EBS snapshot / AMI shared to external account | exfiltration | HIGH | AGGREGATE |
| S3 ransomware via SSE-C encryption-in-place | impact | HIGH | INCIDENT |
| SES sending / identity abuse | impact | MEDIUM | INCIDENT |

### GCP — Cloud Audit Logs (29)

| Chokepoint | Tactic | Priority | Tier |
|---|---|---|---|
| setIamPolicy self/external privileged grant | privilege-escalation | CRITICAL | INCIDENT |
| Backdoor a service account (grant TokenCreator) | privilege-escalation | CRITICAL | CAPABILITY |
| Attach privileged service account (actAs / PassRole-analog) | privilege-escalation | CRITICAL | CAPABILITY |
| actAs-bypass via Deployment Manager / Cloud Build agent | privilege-escalation | HIGH | CAPABILITY |
| Instance created with startup-script + attached SA | privilege-escalation | HIGH | CAPABILITY |
| Org policy constraint weakened | privilege-escalation | HIGH | CAPABILITY |
| Custom role updated to add privileges | privilege-escalation | MEDIUM | CAPABILITY |
| Service-account key creation | credential-access | CRITICAL | INCIDENT |
| SA impersonation — token minting / signing | credential-access | CRITICAL | CAPABILITY `[blind]` |
| Secret Manager secret access | credential-access | HIGH | CAPABILITY `[blind]` |
| Instance metadata SA-token theft | credential-access | HIGH | CAPABILITY `[blind]` |
| New service account created and keyed | persistence | HIGH | CAPABILITY |
| Workload Identity Federation / external IdP added | persistence | HIGH | TRANSLATABLE |
| SSH key added to project/instance metadata | persistence | MEDIUM | CAPABILITY |
| Serverless / scheduled backdoor | persistence | MEDIUM | CAPABILITY |
| Logging sink deletion or disable | defense-evasion | CRITICAL | AGGREGATE |
| Log bucket deletion / retention reduction | defense-evasion | HIGH | CAPABILITY |
| Audit logging disabled via auditConfig | defense-evasion | HIGH | CAPABILITY |
| Telemetry disabled (VPC Flow / DNS / project detach) | defense-evasion | MEDIUM | CAPABILITY |
| Firewall opened to the world | defense-evasion | MEDIUM | CAPABILITY |
| IAM permission brute-forcing | discovery | HIGH | CAPABILITY `[blind]` |
| Org-wide asset enumeration (Cloud Asset Inventory) | discovery | MEDIUM | CAPABILITY `[blind]` |
| Resource enumeration | discovery | MEDIUM | CAPABILITY `[blind]` |
| Valid stolen account vs control plane | initial-access | CRITICAL | INCIDENT |
| Cross-project data transfer via resource IAM sharing | exfiltration | HIGH | INCIDENT |
| Bulk object read from Cloud Storage | exfiltration | HIGH | CAPABILITY `[blind]` |
| Resource hijacking — cryptomining compute | impact | HIGH | INCIDENT |
| GCS bucket / object made public | impact | HIGH | CAPABILITY |
| Data destruction / ransomware | impact | HIGH | CAPABILITY |

### Azure — Activity Log (14)

| Chokepoint | Tactic | Priority | Tier |
|---|---|---|---|
| Elevate access to all subscriptions (tenant-wide) | privilege-escalation | CRITICAL | CAPABILITY |
| RBAC role assignment created | privilege-escalation | HIGH | INCIDENT |
| Custom role definition created/modified | privilege-escalation | MEDIUM | CAPABILITY |
| Key Vault access policy / vault write | credential-access | HIGH | CAPABILITY |
| Storage account key regenerated | credential-access | MEDIUM | CAPABILITY |
| Key Vault secret read | credential-access | HIGH | CAPABILITY `[blind]` |
| Diagnostic settings deleted | defense-evasion | HIGH | CAPABILITY |
| NSG rule opened to the internet | defense-evasion | HIGH | CAPABILITY |
| Defender for Cloud / auto-provisioning disabled | defense-evasion | MEDIUM | CAPABILITY |
| VM run-command execution | execution | HIGH | CAPABILITY |
| App Service (Kudu) command / function keys | execution | MEDIUM | CAPABILITY |
| Managed disk exported via SAS | exfiltration | HIGH | CAPABILITY |
| Storage bulk blob read | exfiltration | HIGH | CAPABILITY `[blind]` |
| Backup / recovery destruction | impact | HIGH | INCIDENT |

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
