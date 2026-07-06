# Chokepoint Entry Schema

One schema for every cloud (AWS / GCP / Azure). **One YAML file per chokepoint**, stored at
`chokepoints/<cloud>/<tactic>/<slug>.yml`. Adapted from the upstream
[iimp0ster/detection-chokepoints](https://github.com/iimp0ster/detection-chokepoints) schema,
with a cloud-agnostic `observability` block (the framework's **Q5 — "can we observe it?"**).

The entry preserves the upstream spine: **what the attacker controls** (variable,
tool-dependent) vs. **what the attacker cannot control** (the invariant — the chokepoint).
Detections anchor to the invariant so they survive tool rotation.

See [`../templates/chokepoint-template.yml`](../templates/chokepoint-template.yml) for a
filled-in worked example.

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | `<cloud>-<slug>`, unique repo-wide, matches the file slug (e.g. `aws-iam-create-policy-version`). |
| `name` | string | yes | Human-readable chokepoint name. |
| `cloud` | enum | yes | `aws` \| `gcp` \| `azure`. Matches the `chokepoints/<cloud>/` folder. |
| `tactic` | enum | yes | MITRE ATT&CK tactic → the `<tactic>/` subfolder. See **Valid tactics**. |
| `attack_technique` | list[string] | yes | MITRE technique IDs (e.g. `[T1098.003]`). |
| `priority` | enum | yes | `CRITICAL` \| `HIGH` \| `MEDIUM`. |
| `prevalence` | enum | yes | `VERY_HIGH` \| `HIGH` \| `MEDIUM` \| `EMERGING`. |
| `difficulty` | enum | yes | Attacker difficulty: `LOW` \| `MEDIUM` \| `HIGH`. |
| `chokepoint` | map | yes | The invariant analysis (Q1–Q4, Q6). See below. |
| `observability` | map | yes | The Q5 verdict against this cloud's audit log. See below. |
| `detection` | map | yes | Three maturity tiers of detection logic. See below. |
| `validation_tier` | enum | yes | Threat-intel backing: `INCIDENT` \| `AGGREGATE` \| `CAPABILITY` \| `TRANSLATABLE`. See below. |
| `actors` | list[string] | no | Named actors documented using this chokepoint. |
| `evolution_timeline` | list | no | Documented variants over time; what changed vs. what stayed invariant. |
| `references` | list[string] | no | MITRE / research links + the relevant `trends/<cloud>-chokepoint-convergence.md`. |
| `related` | list[string] | no | `id`s of linked chokepoints. |

### Valid tactics (subfolder names)

`initial-access` · `credential-access` · `discovery` · `privilege-escalation` ·
`persistence` · `defense-evasion` · `lateral-movement` · `execution` · `exfiltration` · `impact`

## `chokepoint` block (Q1–Q4, Q6)

| Field | Type | Description |
|---|---|---|
| `technique` | string | **Q1** — what the technique is, technically (which APIs / auth flows). |
| `preconditions` | string | **Q2** — the credential type + permission set the attacker must already hold. |
| `attacker_controls` | list[string] | **Q3** — the variables (user agent, source IP, tool, timing, names). |
| `invariant` | string | **Q4 — the chokepoint.** The mandatory operation(s) + the narrowing signal that survives tool rotation. |
| `operations` | list[string] | Cloud-native operation value(s): CloudTrail `eventName` / GCP `methodName` / Azure `operationName`. |
| `variations` | list[string] | **Q6** — every API path that reaches the same outcome. |

## `observability` block (Q5)

| Field | Type | Description |
|---|---|---|
| `status` | enum | `OBSERVABLE` \| `PARTIAL` \| `INGEST_GAP` \| `CONFIRM`. |
| `log_source` | string | `AWS CloudTrail` \| `GCP Cloud Audit Log` \| `Azure Activity Log`. |
| `log_class` | string | The always-on-vs-off dimension: AWS `Management`/`Data`; GCP `Admin Activity`/`Data Access`; Azure `Activity Log`/`data-plane`. |
| `signal_field` | string | Where the discriminating signal lives (a parsed field, or the request body / policy document). Note explicitly when it is NOT a lifted field. |
| `notes` | string | Ingestion caveats + field/method-name confidence. |

> **The recurring cloud gap:** read/data-plane logs are off by default on every cloud —
> AWS S3 `GetObject`, GCP Data Access logs, Azure Key Vault/Storage data-plane. Entries that
> depend on them are `INGEST_GAP` with the enablement noted.

## `detection` block — three maturity tiers

Mirrors the upstream Research → Hunt → Analyst maturity model.

| Tier | Fields | FP rate | Purpose |
|---|---|---|---|
| `research` | `logic`, `fp_rate: high` | high | Establish baseline visibility. |
| `hunt` | `logic`, `fp_rate: medium` | medium | Reduce noise, keep coverage. |
| `analyst` | `logic`, `fp_rate: low`, `severity` | low | Production alert; carries `severity` (`LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL`). New detections default `HIGH`. |

## `validation_tier` — threat-intel backing

How strong the public evidence is that real actors exercise this chokepoint (see the
`trends/<cloud>-chokepoint-convergence.md` docs):

- **INCIDENT** — a named actor was documented performing it in this cloud.
- **AGGREGATE** — vendor telemetry across many incidents quantifies the behavior class.
- **CAPABILITY** — demonstrated feasible (PoC/research), not yet an attributed incident.
- **TRANSLATABLE** — documented in another cloud; the equivalent here is inferred.

## Qualification test

> If the attacker switches tools tomorrow, does this detection still fire?

If yes → it is a chokepoint. If it keys on a tool signature, user agent, IP, or session name
(all attacker-controlled), it is not — move the anchor to the invariant.
