# Chokepoint Entry Schema

Field definitions and valid enum values for `chokepoints/<tactic>/<name>.yml` entries.
Adapted from the upstream
[iimp0ster/detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints)
schema, with a cloud-specific `observability` block that records framework
**Q5 — "can we observe it?"** against AWS CloudTrail.

The entry preserves the upstream spine: **what the attacker controls** (variable,
tool-dependent) vs. **what the attacker cannot control** (the invariant — the chokepoint).
Detections anchor to the invariant so they survive tool rotation.

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Tactic-prefixed slug, unique across the repo (e.g. `iam-create-policy-version`). |
| `name` | string | yes | Human-readable chokepoint name. |
| `tactic` | enum | yes | MITRE ATT&CK tactic → the `chokepoints/<tactic>/` folder. See **Valid tactics**. |
| `attack_technique` | list[string] | yes | MITRE technique IDs (e.g. `[T1098.003]`). |
| `priority` | enum | yes | Detection priority: `CRITICAL` \| `HIGH` \| `MEDIUM`. |
| `prevalence` | enum | yes | Real-world frequency: `VERY_HIGH` \| `HIGH` \| `MEDIUM` \| `EMERGING`. |
| `difficulty` | enum | yes | Attacker difficulty to execute: `LOW` \| `MEDIUM` \| `HIGH`. |
| `chokepoint` | map | yes | The invariant analysis (Q1–Q4, Q6). See below. |
| `observability` | map | yes | The Q5 verdict against CloudTrail. See below. |
| `detection` | map | yes | Three maturity tiers of detection logic. See below. |
| `variations` | list[string] | no | Other API paths to the same outcome (Q6). |
| `evolution_timeline` | list | no | Documented variants over time; what changed vs. what stayed invariant. |
| `raw_logs` | list | no | Sample (redacted) telemetry for validation. |
| `related` | list[string] | no | `id`s of linked chokepoints. |
| `references` | list[string] | no | External research / MITRE links. |

### Valid tactics (folder names)

`initial-access` · `credential-access` · `discovery` · `privilege-escalation` ·
`persistence` · `defense-evasion` · `lateral-movement` · `exfiltration` · `impact`

## `chokepoint` block (Q1–Q4, Q6)

| Field | Type | Description |
|---|---|---|
| `technique` | string | **Q1** — what the technique is, technically: which AWS APIs / auth flows. |
| `preconditions` | string | **Q2** — credential type and permission set the attacker must already hold. |
| `attacker_controls` | list[string] | **Q3** — the variables (user agent, source IP, tool, timing, names, policy contents). |
| `invariant` | string | **Q4 — the chokepoint.** Mandatory CloudTrail `eventName`(s) + the narrowing signal that survives tool rotation. |
| `event_names` | list[string] | Canonical CloudTrail `eventName` value(s). |

## `observability` block (Q5)

| Field | Type | Description |
|---|---|---|
| `status` | enum | `OBSERVABLE` (event present, usable fields) \| `PARTIAL` (some variants/fields missing) \| `INGEST_GAP` (event not typically forwarded) \| `CONFIRM` (verify with a live query in your env). |
| `cloudtrail_event_category` | enum | `Management` \| `Data` \| `Insight`. |
| `signal_field` | string | Where the discriminating signal lives (a top-level field, or `requestParameters.*` / the policy document / `additionalEventData.*`). **Note explicitly** when it is *not* a lifted top-level field. |
| `ingestion_notes` | string | Known gaps (e.g. S3 `GetObject` data events, console sign-in forwarding) and parser caveats. |

## `detection` block — three maturity tiers

| Tier | Field(s) | FP rate | Purpose |
|---|---|---|---|
| `research` | `logic`, `fp_rate: high` | high | Establish baseline visibility. |
| `hunt` | `logic`, `fp_rate: medium` | medium | Reduce noise, keep coverage. |
| `analyst` | `logic`, `fp_rate: low`, `severity` | low | Production alert; carries severity. |

**Severity scale:** `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL`. New detections default to
`HIGH`; `CRITICAL` only when 100 %-confident (pages on-call). `MEDIUM` for pure
discovery / lateral-movement precursors.

## Qualification test

> If the attacker switches tools tomorrow, does this detection still fire?

If yes → it is a chokepoint. If it keys on a tool signature, user agent, IP, or session
name (all attacker-controlled), it is not — move the anchor to the invariant.
