# AWS Detection Chokepoints

> **TTPs evolve. Chokepoints don't.**

A catalog of **invariant control-plane prerequisites** for AWS attack techniques — the
mandatory API calls and request parameters an attacker *cannot avoid* regardless of the
tool they use — and the detections that anchor to them.

This project applies the [detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints)
methodology (built for EDR/endpoint) to **AWS CloudTrail**. Instead of chasing tool
signatures, user agents, or IOCs that rotate faster than we can write rules, we anchor
detections to the *unavoidable technical requirements* of each technique: every cloud
intrusion must authenticate, obtain or mint credentials, enumerate what it has, escalate
or move via IAM, and touch data or persistence through a **finite set of control-plane
APIs**.

---

## The idea

A **chokepoint** is a technical prerequisite an attacker cannot design around. Ransomware
crews, infostealers, and hands-on-keyboard operators all converge on the *same* handful of
AWS APIs — `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, `CreateAccessKey`,
`ModifySnapshotAttribute`, `PutBucketPolicy`, `StopLogging` — because the AWS control plane
gives them no other path to the outcome. Tool choice is variable; the CloudTrail
`eventName` and its request parameters are not.

Detections built on chokepoints survive tool rotation. A rule that keys on a specific
offensive tool's user agent dies the day the attacker recompiles. A rule that keys on
*"a new default IAM policy version granting `Action:*`"* fires no matter what tool wrote it.

## The six-question framework

Adapted from Matt Graeber's approach, applied to every entry in this repo:

1. **What is the technique, technically?** — which AWS APIs / auth flows.
2. **What preconditions enable it?** — credential type, permission set already held.
3. **What does the attacker control?** — user agent, source IP, tool, timing, names.
4. **What can't the attacker control?** ← **the chokepoint** — the mandatory CloudTrail
   `eventName`(s) plus the narrowing invariant (a wildcard action, an external principal,
   an off-instance credential use, a new principal pair).
5. **Can we observe it?** — is the event in CloudTrail, and does the discriminating field
   survive to your SIEM? (See [`coverage/`](coverage/).)
6. **What are all the variations?** — every API path that reaches the same outcome
   (e.g. the PassRole family across `RunInstances`, `CreateFunction`, `CreateStack`, …).

**Qualification test for any detection:** *"If the attacker switches tools tomorrow, does
this still fire?"* If it keys on a tool signature, UA, IP, or session name — it's not a
chokepoint. Move the anchor to the invariant.

## Detection maturity model

Every chokepoint carries detection logic at three tiers:

| Tier | FP rate | Purpose |
|---|---|---|
| **Research** | high | Establish baseline visibility — every occurrence, minimal filter. |
| **Hunt** | medium | Add the narrowing invariant + grouping; reduce noise, keep coverage. |
| **Analyst** | low | Production alert — tightest invariant + allowlists built from *your own* baseline data. |

The promotion path is deliberate: baseline with Research, learn your environment's noise,
tune to Hunt, and only promote to Analyst once the false-positive sources are understood
and allowlisted from **real** data — never guesses.

---

## Repository layout

```
chokepoints/        YAML entries, one per chokepoint, organised by ATT&CK tactic.
                    Each carries the Q1–Q6 invariant analysis, prevalence/difficulty,
                    tool variations, observability notes, and 3-tier detection logic.
sigma-rules/        Portable Sigma detections (product=aws, service=cloudtrail).
trends/             Threat-intel convergence evidence — real campaigns mapped to chokepoints.
attack-chains/      Actor-convergence analyses — which groups share which chokepoints.
coverage/           Observability reference: which CloudTrail events carry the signal,
                    which field the invariant lives in, and common ingestion gaps.
emulation/          Safe, lab-only validation commands (aws-cli + stratus-red-team refs).
schema/             Field definitions and valid enum values for chokepoint entries.
templates/          Contribution template.
```

## The AWS chokepoint catalog

Control-plane invariants grouped by ATT&CK tactic. ✅ = worked entry in this repo.

| Tactic | Chokepoints |
|---|---|
| **Initial Access** | ✅ Console login (MFA anomaly / impossible geo) · Federated sign-in anomaly |
| **Credential Access** | ✅ Secrets Manager mass read · Long-lived key use · EC2 role creds used off-instance · STS token minting |
| **Discovery** | ✅ IAM/account enumeration burst · Bucket enumeration · Whoami orientation |
| **Privilege Escalation** | ✅ Policy-version wildcard · ✅ Inline-policy self-escalation · ✅ Privileged managed-policy attach · PassRole family (compute-with-role) · Login profile for another user |
| **Persistence** | ✅ Role trust-policy external principal · ✅ Federation/IdP backdoor · Backdoor identity · ✅ Event-driven backdoor |
| **Defense Evasion** | ✅ CloudTrail/Config/FlowLog tampering · ✅ KMS key sabotage |
| **Lateral Movement** | ✅ Cross-account AssumeRole to new principal · Stolen-session use (impossible travel) |
| **Exfiltration** | ✅ Snapshot/AMI shared external · S3 cross-account replication · S3 made public · S3 bulk object read |
| **Impact** | ✅ SES sending/identity abuse · ✅ S3 SSE-C ransomware · Backup/snapshot destruction · Resource hijack (cryptomining) |

See [`coverage/observability-matrix.md`](coverage/observability-matrix.md) for the full
event → invariant → buildability reference.

## Threat-intel backing

These chokepoints aren't theoretical. [`trends/aws-chokepoint-convergence.md`](trends/aws-chokepoint-convergence.md)
maps **16 real, publicly-documented AWS campaigns** — LUCR-3 / Scattered Spider, SCARLETEEL,
AMBERSQUID, EleKtra-Leak, TeamTNT, Androxgh0st, Codefinger, and more — to the control-plane
chokepoints each one had no choice but to touch. Different actors, different tooling
(CloudShell, S3 Browser, Terraform, DockerHub miners); the same CloudTrail API calls.

Every chokepoint entry carries a `references:` line with a **validation tier**:

- **INCIDENT** — a named actor was documented calling the specific API in a real breach.
- **AGGREGATE** — vendor telemetry across many incidents shows the behavior class is prevalent.
- **CAPABILITY** — demonstrated feasible (PoC/research), not yet attributed in the wild.
- **ANALOGUE** — observed in another cloud; the AWS equivalent is inferred.

We label honestly — e.g. AWS KMS-deletion ransomware is CAPABILITY-only (real-world only in
Azure so far), and the "Scattered Spider added an AWS SAML provider" claim is a common
misattribution (their federation abuse is at the Okta/Entra tenant level, not an AWS API).
Aggregate backing includes CrowdStrike (valid-account abuse = 35% of cloud incidents),
Datadog (60% of AWS keys are >1 year old), Unit 42 (bulk storage downloads +305%, snapshot
exports +45% in 2024), and Sysdig (initial-access → impact in ≤10 minutes). Full citations
in the trends doc.

---

## How to use this repo

- **Detection engineers:** lift the Sigma rules, or the invariant analysis, and adapt the
  Analyst-tier allowlists to your environment. **Do not ship the Analyst tier without
  baselining against your own 30-day data** — the allowlist accounts, scanner roles, and
  operating geos are environment-specific placeholders here.
- **Threat hunters:** the Research-tier queries are your starting hunts. The
  [`attack-chains/`](attack-chains/) docs show which chokepoints to prioritise per actor.
- **Red teamers:** [`emulation/`](emulation/) has safe, lab-only commands to generate the
  telemetry each chokepoint depends on.

## A note on portability

The invariant analysis is SIEM-agnostic. Detections are provided in **Sigma** so they
convert to any backend. Field names follow CloudTrail's **native** schema (`eventName`,
`requestParameters.*`, `userIdentity.*`); map them to your platform's parsed field names.
Two lessons that bite everyone, documented in
[`coverage/observability-matrix.md`](coverage/observability-matrix.md):

1. The discriminating signal for most IAM/policy chokepoints lives in
   **`requestParameters` / the policy document** — confirm your parser exposes it.
2. **Field-to-field comparisons** (e.g. "caller account ≠ resource account") are a common
   footgun — many query languages compare a field to the *literal string* of the other
   field name unless you use an explicit comparison function. Validate on real data.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the entry [`templates/`](templates/) +
[`schema/`](schema/). New chokepoints must pass the qualification test and cite the
observable CloudTrail event(s).

## License

[MIT](LICENSE). Detection logic and methodology are provided as-is for defensive use.

## Acknowledgements

Methodology and structure adapted from
[iimp0ster/detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints).
