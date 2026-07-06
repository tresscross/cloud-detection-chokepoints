# GCP Chokepoint Convergence — the threat-intel evidence

Companion to [`aws-chokepoint-convergence.md`](aws-chokepoint-convergence.md), for Google
Cloud. Same thesis — *TTPs evolve, chokepoints don't* — applied to GCP Cloud Audit Logs.
Different crews converge on the same control-plane invariants: identity abuse in, IAM
manipulation to escalate/persist, log destruction to hide, compute hijack to profit.

## Validation tiers

- **INCIDENT** — a named actor was documented performing the technique in GCP.
- **AGGREGATE** — vendor/provider telemetry across many incidents quantifies the behavior.
- **CAPABILITY** — demonstrated feasible (research/PoC/simulation), not yet an attributed GCP incident.
- **TRANSLATABLE** — documented in AWS/Azure; the GCP equivalent is inferred, not confirmed.

> **Honesty note carried from the research:** much granular cloud-identity forensics for the
> big identity crews (Scattered Spider/UNC3944, LUCR-3) is **AWS/Azure-documented** — in GCP
> they appear as a named target and exfil destination more than as per-`methodName` casework.
> UNC4899's chain spans GCP+AWS and public write-ups don't cleanly separate the clouds. We
> label those TRANSLATABLE rather than overclaim GCP attribution.

---

## The aggregate picture (Google Threat Horizons, 2025–2026)

- **Identity is the door.** Identity issues were the initial-access vector in **83%** of
  cloud/SaaS incidents (H2 2025). Weak/absent credentials were the single top vector at
  **47.1%** (H1 2025), later overtaken by software/third-party vulns at **44.5%** (H2 2025).
- **Data is the target.** Data was targeted in **73%** of cloud incidents; **28%** showed
  extortion indicators (H2 2025).
- **Compute is the payday.** **~65%** of compromised cloud accounts were used for
  cryptomining; one incident spun up **1,600+ GPU VMs** from a single compromised App Engine
  default service account.
- **Anti-forensics is standard.** All major ransomware crews now delete logs, core dumps,
  and backups.
- Google **auto-disables detected leaked service-account keys** (default since 2024-06-16),
  raising the value of catching key *creation* and impersonation at the source.

Source: Google Cloud Threat Horizons reporting, 2025–2026. (Figures transcribed from the
research pass; confirm against the current Threat Horizons report before external citation.)

---

## Actor convergence on shared GCP chokepoints

| Convergence chokepoint | Actors converging | Tier | Chokepoint IDs |
|---|---|---|---|
| Human identity / IdP / help-desk social eng | Scattered Spider/UNC3944, LUCR-3, UNC6040 (ShinyHunters) | TRANSLATABLE (identity door is cloud-agnostic) | CP-GCP-IA-01 |
| Service-account / non-human identity abuse | UNC4899 (CI/CD SA token), TeamTNT/SCARLETEEL, leaked-key crews | INCIDENT (SA-key/token abuse broadly documented) | CP-GCP-CA-01/02, PE-02/03 |
| OAuth / OIDC / federation trust (MFA bypass) | UNC6395 (Salesloft Drift), UNC6426 (npm→OIDC) | INCIDENT (OAuth token theft) / TRANSLATABLE (GCP WIF) | CP-GCP-PERS-02, CP-GCP-IA-01 |
| Log / backup destruction (anti-forensics) | Ransomware crews broadly | AGGREGATE (standard across crews) | CP-GCP-DE-01/02/03 |
| Compute hijack for cryptomining | Cryptomining crews (App Engine default-SA case) | INCIDENT + AGGREGATE (~65% of compromised accounts) | CP-GCP-IMP-01 |

Codefinger (AWS S3 SSE-C ransomware) and UNC6426's admin-role creation (AWS OIDC) are
included in the chokepoint entries as **TRANSLATABLE** techniques — real elsewhere, plausible
on GCP, not confirmed GCP incidents.

---

## The two facts that define GCP observability (and the biggest gap)

1. **Admin Activity is always on; Data Access is OFF by default** (only BigQuery data reads
   are on). This cleanly splits every chokepoint into *observable now* vs *blind until enabled*:

   | Observable now (Admin Activity) | Blind by default (Data Access) |
   |---|---|
   | `CreateServiceAccountKey`, `CreateServiceAccount` | `GenerateAccessToken`/`SignBlob`/`SignJwt` (impersonation) |
   | `SetIamPolicy` grants, auditConfig changes | `AccessSecretVersion` (secret reads) |
   | resource create (compute/functions/run/build/DM) | `testIamPermissions`/`getIamPolicy` (recon) |
   | logging sink/bucket delete, firewall, org policy | Cloud Asset `SearchAll*`, list/get enumeration |
   | compute instance create (mining), resource sharing | `storage.objects.get` (bulk exfil, T1530) |

   **This Data-Access-off gap is the direct GCP analogue of the AWS "S3 GetObject not
   ingested" gap.** Impersonation, secret reads, recon, and object-read exfil are invisible
   until Data Access logging is enabled per service. Highest-leverage config change: enable
   `DATA_READ`/`ADMIN_READ` for `iamcredentials`, `secretmanager`, `cloudresourcemanager`,
   `cloudasset`, and `storage`.

2. **`iam.serviceAccounts.actAs` has no audit event of its own** — it's a permission check at
   resource-creation time. Impersonation-via-attach is only visible through the *host* create
   event (compute/functions/run/scheduler/deploymentmanager/cloudbuild) with the attached SA
   inspected. Deployment Manager and Cloud Build sidestep `actAs` by running as a default
   Editor agent, so mere use of those create rights by a low-privilege principal is the
   finding. **This is the GCP analogue of the AWS PassRole family.**

### Field-reality caveats (validate before shipping any GCP rule)

- **`serviceData` is deprecated** and frequently dropped from *exported* logs. `SetIamPolicy`
  binding/audit-config deltas (`policyDelta.bindingDeltas`, `auditConfigDeltas`) that a rule
  relies on may be present in the raw event but unreliable — a "policy contains role X" match
  fires on *every* policy (which always contains `roles/owner` etc.), so you must match the
  **ADD delta**, and even then privileged-role ADDs are dominated by IaC/automation. Prefer
  `protoPayload.metadata`; validate every delta-based rule against a live sample.
- **`callerIp` redaction** — Google-internal service-to-service calls show `"private"` /
  `"gce-internal-ip"`; IP-based rules can't see intra-Google moves.
- **`PERMISSION_DENIED` principal redaction** — failed read-only calls by a *user* identity
  can lose `principalEmail` attribution (service accounts are retained).
- **MITRE v19 (2026-04-28)** moved T1562 "Impair Defenses" to tactic **TA0112**; classic
  Defense Evasion (TA0005) became "Stealth". Entries here use pre-v19 IDs — re-map before
  hard-coding.

---

## Where the invariants land

Chokepoint entries with per-entry `methodName`, audit-log class, actors, and tier are in
[`../chokepoints/gcp/`](../chokepoints/gcp/) (29 entries across 7 tactics). Observability and
the buildable-vs-blocked split are folded into
[`../coverage/observability-matrix.md`](../coverage/observability-matrix.md). Method-name
strings were sourced from Stratus Red Team, Datadog Security Labs, Mitiga, and Rhino, and
cross-checked; strings that couldn't be confirmed verbatim are flagged in the entries.
