# Attack chains — actor convergence

The value of chokepoints is empirical: **different actors, different tools, the same
control-plane APIs.** These docs map real cloud-intrusion patterns to the chokepoints they
share, so you can prioritise coverage by how many actor playbooks a single detection breaks.

Each chain lists the stages and the chokepoint `id`s that fire on them. The takeaway is
always the same — a handful of chokepoints sit on the critical path of nearly every cloud
intrusion, regardless of the crew.

| Chain | Theme | Highest-leverage shared chokepoints |
|---|---|---|
| [Cloud account takeover](cloud-account-takeover-convergence.md) | Phished/stolen creds → escalate → persist → exfil | `console-login-anomaly`, `iam-enumeration-burst`, `iam-create-policy-version`, `iam-role-trust-external-principal`, `secrets-manager-mass-read` |
| SES / email-fraud crews | Exposed keys → SES weaponisation | `secrets-manager-mass-read`, `ses-sending-identity-abuse` |
| Cryptomining crews | Access → resource hijack for compute | `iam-enumeration-burst`, PassRole family, resource-hijack (RunInstances) |
| Ransomware / extortion in cloud | Access → destroy recoverability → exfil | `kms-key-sabotage`, `ebs-snapshot-ami-shared-external`, backup destruction, `cloudtrail-config-tampering` |

> Names of specific threat groups change and attributions shift; the **stages and the
> chokepoints do not**. Track the invariants, not the actor branding.
