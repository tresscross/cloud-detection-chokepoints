# Attack chain — Cloud account takeover (convergence)

A generic hands-on-keyboard cloud intrusion, from initial access to impact, annotated with
the chokepoint that fires at each stage. Whether the operator is a financially-motivated
crew, an access broker, or a red team, the control-plane path is nearly identical.

## Stages → chokepoints

| # | Stage | What the attacker does | Chokepoint(s) that fire |
|---|---|---|---|
| 1 | **Initial access** | Sign in with phished/stolen console creds or a leaked long-lived key | `initial-access/console-login-anomaly` |
| 2 | **Orientation** | `GetCallerIdentity`; enumerate identities, roles, policies, account | `discovery/iam-enumeration-burst` |
| 3 | **Credential access** | Loot Secrets Manager / SSM parameters / key material | `credential-access/secrets-manager-mass-read` |
| 4 | **Privilege escalation** | Self-grant admin via a new default policy version, inline policy, or privileged attach | `privilege-escalation/iam-create-policy-version`, `…/iam-inline-policy-self-escalation`, `…/iam-privileged-policy-attach` |
| 5 | **Persistence** | Add a foreign principal to a role trust policy; stand up a rogue IdP; wire an event trigger | `persistence/iam-role-trust-external-principal`, `…/iam-federation-idp-created`, `…/eventbridge-cross-account-target` |
| 6 | **Defense evasion** | Stop the trail / recorder; sabotage the KMS key protecting the data | `defense-evasion/cloudtrail-config-tampering`, `…/kms-key-sabotage` |
| 7 | **Lateral movement** | Assume roles across accounts to reach the crown-jewel account | `lateral-movement/sts-cross-account-new-principal` |
| 8 | **Exfiltration** | Share a snapshot/AMI out; enable cross-account S3 replication; make a bucket public | `exfiltration/ebs-snapshot-ami-shared-external` |
| 9 | **Impact** | Destroy backups / keys, or hijack SES/compute | `defense-evasion/kms-key-sabotage`, `impact/ses-sending-identity-abuse` |

## Why this matters for coverage

Notice how **stages 2, 4, and 5 are unavoidable** for any operator who wants durable admin
in the account. That is where to invest first:

1. **`iam-enumeration-burst`** — nearly every intrusion orients here before it escalates.
2. **The three privilege-escalation chokepoints** — the finite set of "grant myself admin"
   primitives. Cover all three (managed-version, inline, privileged-attach) or the attacker
   just uses the uncovered one.
3. **`iam-role-trust-external-principal`** — the highest-value persistence move, because it
   survives every credential rotation your IR team performs.

A defender who covers just these five breaks the chain of the overwhelming majority of
cloud-takeover playbooks — because the attacker has nowhere else to route the technique.
