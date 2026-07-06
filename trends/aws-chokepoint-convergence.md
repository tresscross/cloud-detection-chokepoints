# AWS Chokepoint Convergence — the threat-intel evidence

> Kaspersky analyzed eight major ransomware operations in 2022 and found they all share the
> same core kill chain — External Remote Services, command interpreters, WMI, LSASS dumping
> in *every* group; shadow-copy deletion and service-stopping in 7 of 8. **The tools rotate
> constantly. The requirements don't.**

The same is true in AWS. Below are **real, publicly-documented AWS intrusions** — different
actors, different tooling (CloudShell, S3 Browser, pacu-style scripts, Terraform, custom
Lambda scanners, DockerHub miners) — mapped to the control-plane chokepoints they each had
no choice but to touch. Every campaign and every API here is drawn from a primary source
cited at the bottom; load-bearing claims were re-verified against the source page.

## Validation tiers

Each chokepoint carries a **validation tier** — how strong the public evidence is:

- **INCIDENT** — a named actor was documented calling the specific AWS API in a real breach.
- **AGGREGATE** — vendor telemetry across many incidents quantifies the behavior class as prevalent.
- **CAPABILITY** — demonstrated feasible (PoC/research/simulation), not yet seen attributed in the wild.
- **ANALOGUE** — observed in another cloud (Azure/GCP); the AWS equivalent is inferred.

We label honestly: a chokepoint being CAPABILITY-only is not a weakness of the detection —
it means you get to catch it *before* it shows up in someone's breach report.

---

## The aggregate picture (the "8 ransomware ops" equivalent)

Independent vendors, independent telemetry sets, same conclusion: **cloud intrusion is
credential-driven, and post-access behavior collapses onto a small set of IAM / data /
compute APIs.**

- **Valid-account abuse is the #1 cloud initial-access method — 35% of cloud incidents (H1 2024).** New/unattributed cloud intrusions **+26% YoY**; access-broker ads selling stolen creds **+50% YoY**. — *CrowdStrike, 2025 Global Threat Report.*
- **60% of AWS IAM users have an access key older than one year**; long-lived credentials are "the most common cause of publicly documented cloud security breaches." — *Datadog, State of Cloud Security 2024.*
- **Stolen credentials = 16% of all intrusions, the #2 initial vector** (behind exploits at 33%). — *Mandiant, M-Trends 2025.*
- Across 2024, cloud **IAM "impossible travel" alerts +116%**, **bulk cloud-storage object downloads +305%**, **cloud snapshot exports +45%**, total cloud alerts **+388%**. — *Palo Alto Unit 42, 2025 Cloud Security Alert Trends.*
- Cloud attackers go **initial-access → impact in ≤10 minutes**; one compromised account was used to **spin up 500+ cryptomining instances every 20 seconds**. — *Sysdig, 2024 Global Threat Report.*
- Weak/absent credentials were the top cloud initial-access vector at **47% (H1 2024)**, misconfiguration second at 30%. — *Google Cloud, Threat Horizons* [figure via secondary reporting; see sources].

The through-line: **(1) valid credentials in, (2) IAM enumeration + manipulation, (3) bulk
data/snapshot exfil, (4) resource-hijack provisioning.** Those are exactly the chokepoint
clusters below.

---

## Campaigns analyzed

| Campaign / actor | Year | What they did in AWS | Primary source |
|---|---|---|---|
| **LUCR-3 / Scattered Spider** | 2023 | CloudShell → scrape all Secrets Manager secrets; IAM backdoor users/keys; `StopLogging`/`DeleteTrail`; S3 theft via S3 Browser | Permiso |
| **Scattered Spider** | 2025 | S3 enumeration + exfil to adversary buckets (`ListBuckets`/`ListObjects`) | CrowdStrike |
| **SCARLETEEL 1.0** | 2023 | IMDSv1 role-cred theft; `GetCallerIdentity`/`ListBuckets`; `StopLogging`; ~1 TB S3 exfil; miner | Sysdig |
| **SCARLETEEL 2.0** | 2023 | `CreateUser`/`CreateAccessKey` admin persistence; 42 × c5.metal/r5a.4xlarge mining | Sysdig |
| **AMBERSQUID** | 2023 | `CreateRole`+`AttachRolePolicy` (Admin); mining across ECS/SageMaker/CodeBuild/Amplify | Sysdig |
| **EleKtra-Leak** | 2023 | GitHub-exposed IAM keys used in ~4 min; `RunInstances` c5a.24xlarge across regions | Unit 42 |
| **TeamTNT** | 2021 | ~70 AWS CLI enum calls: `ListUsers`/`ListRoles`/`GetAccountAuthorizationDetails`/`ListBuckets` | Unit 42 |
| **Unnamed cryptomining (GuardDuty ETD)** | 2025 | `RunInstances`+`CreateAutoScalingGroup` (GPU); `CreateUser`/`CreateAccessKey`/`AttachUserPolicy` (SES) backdoor | AWS Security Blog |
| **Androxgh0st** | 2024 | Scan exposed `.env` → AWS keys; create IAM users/policies; SMTP/SES email abuse *(behavior described, MITRE-level)* | CISA/FBI AA24-016A |
| **SES-pionage** | 2023 | Exposed AKIA keys → `GetSendQuota`/`ListIdentities` → `UpdateAccountSendingEnabled` spam | Permiso |
| **Exposed-`.env` extortion** | 2024 | 110k domains scanned; `GetCallerIdentity`/`ListUsers`; `CreateRole`+`AttachRolePolicy` Admin; SES; S3 exfil+delete+ransom | Unit 42 |
| **Cloud email takeover** | 2025 | `PutAccountDetails` (multi-region SES sandbox escape) + `CreateEmailIdentity` for phishing | Wiz |
| **Honeytoken persistence case** | 2025 | Leaked key hit by 5 IPs in 150 min; SES recon; `CreateUser`/`CreateLoginProfile`; `GetFederationToken`; Lambda "persistence-as-a-service" | Datadog |
| **Codefinger** | 2025 | S3 ransomware: `PutObject`/`CopyObject` with SSE-C (`x-amz-server-side-encryption-customer-algorithm`); 7-day lifecycle-delete timer | Halcyon |
| **Invictus IR S3 case** | 2024 | Exposed key → `PutBucketVersioning`=Suspended → bulk object delete + ransom; `CreateUser` (denied); SES probe | Invictus IR |
| **Storm-0501** *(Azure ANALOGUE)* | 2025 | Delete backups/snapshots + stand up attacker CMK + delete key to extort — **zero AWS APIs; cross-cloud analogue only** | Microsoft MSTIC |

---

## Chokepoint × campaign matrix

The core deliverable: which real campaigns exercised each chokepoint, and how well-evidenced
it is. `→` lists the confirmed CloudTrail eventName(s).

| Chokepoint | Tier | Campaigns (confirmed API) |
|---|---|---|
| **credential-access/long-lived-key-use** | INCIDENT + AGGREGATE | SCARLETEEL 1.0, EleKtra-Leak, TeamTNT, Codefinger, Invictus, LUCR-3, Datadog, Unit 42 extortion · *(Datadog: 60% of AWS keys >1yr old)* |
| **credential-access/secrets-manager-mass-read** → `GetSecretValue` | INCIDENT | LUCR-3 (scrapes *all* secrets via CloudShell) |
| **credential-access/sts-token-minting** → `GetFederationToken` | INCIDENT | Datadog honeytoken case *(note: `GetFederationToken`, not `GetSessionToken`)* |
| **discovery/iam-enumeration-burst** → `ListUsers`/`ListRoles`/`GetAccountAuthorizationDetails` | INCIDENT | TeamTNT (~70 calls), Unit 42 extortion |
| **discovery/whoami-orientation** → `GetCallerIdentity` | INCIDENT | SCARLETEEL 1.0, Unit 42 extortion, Wiz |
| **discovery/bucket-enumeration** → `ListBuckets`/`ListObjects` | INCIDENT | SCARLETEEL 1.0, TeamTNT, Scattered Spider |
| **discovery/ses-recon** → `GetSendQuota`/`GetAccount`/`ListIdentities` | INCIDENT | SES-pionage, Unit 42 extortion, Wiz, Datadog |
| **privilege-escalation/iam-privileged-policy-attach** → `AttachRolePolicy`/`AttachUserPolicy` (Admin) | INCIDENT | AMBERSQUID, Unit 42 extortion, GuardDuty campaign, Datadog |
| **privilege-escalation/iam-backdoor-identity** → `CreateUser`/`CreateAccessKey`/`CreateLoginProfile` | INCIDENT | LUCR-3, SCARLETEEL 2.0, GuardDuty campaign, Datadog, Androxgh0st *(described)* |
| **privilege-escalation/iam-create-policy-version** / inline | AGGREGATE | *(no attributed incident names the verb; Unit 42 IAM-anomaly telemetry +116% covers the class)* |
| **persistence/iam-role-trust-external-principal** → `CreateRole` (for attacker Lambda) | INCIDENT *(loose)* | Unit 42 extortion, Datadog |
| **persistence/iam-federation-idp-created** → `CreateSAMLProvider`/`CreateOIDCProvider` | CAPABILITY | **No verified AWS incident.** Scattered Spider's federation abuse (CISA AA23-320a) is at the **IdP tenant level (Okta/Entra), not an AWS API** — widely misattributed; we do not claim it |
| **defense-evasion/cloudtrail-config-tampering** → `StopLogging`/`DeleteTrail` | INCIDENT | LUCR-3, SCARLETEEL 1.0 |
| **defense-evasion/kms-key-sabotage** → `ScheduleKeyDeletion`/`DisableKey`/`PutKeyPolicy` | CAPABILITY + ANALOGUE | AWS: PoC/research only (e.g. "RansomWhen"). Real-world: Storm-0501 (Azure CMK abuse) |
| **lateral-movement/sts-cross-account-new-principal** → `AssumeRole` | AGGREGATE | *No clean incident (SCARLETEEL pivoted with static keys, not AssumeRole). Unit 42 impossible-travel +116% covers cross-account identity anomaly* |
| **exfiltration/s3-bulk-object-read** → `GetObject`/`ListObjects` | INCIDENT + AGGREGATE | SCARLETEEL 1.0 (~1 TB), LUCR-3, Invictus, Scattered Spider · *(Unit 42: bulk downloads +305%)* — **caveat: S3 data events are off by default** |
| **exfiltration/ebs-snapshot-ami-shared-external** → `ModifySnapshotAttribute` | AGGREGATE | *No attributed incident found; only simulation frameworks. But Unit 42 snapshot-export alerts +45% (2024)* |
| **impact/resource-hijack-cryptomining** → `RunInstances`/`CreateAutoScalingGroup` | INCIDENT + AGGREGATE | SCARLETEEL 2.0, EleKtra-Leak, AMBERSQUID, GuardDuty campaign · *(Sysdig: 500 instances/20s)* |
| **impact/ses-sending-identity-abuse** → `VerifyEmailIdentity`/`UpdateAccountSendingEnabled` / `CreateEmailIdentity`/`PutAccountDetails` (SES v2) | INCIDENT | SES-pionage, Unit 42 extortion, Wiz, GuardDuty campaign, Androxgh0st *(described)* |
| **impact/backup-destruction** → `PutBucketVersioning`(Suspended)/object-delete/lifecycle | INCIDENT + ANALOGUE | Codefinger (lifecycle), Invictus (versioning-suspend+delete); Storm-0501 (Azure snapshot/vault deletes) |
| **impact/s3-sse-c-ransomware** → `PutObject`/`CopyObject` + `x-amz-server-side-encryption-customer-algorithm` | INCIDENT | Codefinger *(novel 2025 TTP — see chokepoints/impact/s3-sse-c-ransomware.yml)* |

---

## What this validates — and what it doesn't

**Strongly incident-validated** (independent actors, named APIs, real breaches):
`long-lived-key-use`, `iam-backdoor-identity`, `iam-privileged-policy-attach`,
`secrets-manager-mass-read`, `cloudtrail-config-tampering`, `bucket-enumeration` /
`iam-enumeration-burst` / `whoami-orientation`, `s3-bulk-object-read`,
`resource-hijack-cryptomining`, `ses-sending-identity-abuse`, and the new
`s3-sse-c-ransomware`. These sit on the critical path of nearly every documented AWS
intrusion — **the tooling differs every time; these API calls don't.**

**Honest gaps — do not overclaim:**

1. **`iam-federation-idp-created` has no verified AWS incident.** Scattered Spider's famous
   "added a federated IdP" is documented by CISA at the **SSO-tenant (Okta/Entra) level**, not
   as an AWS `CreateSAMLProvider` call. We keep the chokepoint (it's a real primitive and the
   AWS API is low-base-rate/high-value) but label it CAPABILITY, not INCIDENT.
2. **KMS ransomware in AWS is PoC-only.** Real key-destruction extortion has been seen in
   **Azure** (Storm-0501), not yet attributed in AWS. Detect it before it arrives.
3. **Snapshot/AMI cross-account share for exfil** shows up in *aggregate* telemetry (Unit 42
   +45%) and simulation frameworks, but we found no *attributed* public incident naming
   `ModifySnapshotAttribute`. Treated as AGGREGATE-validated.
4. **`sts-cross-account-new-principal`** is inferred from IAM-anomaly aggregates, not a clean
   named incident (documented cross-account pivots used *static keys*, not `AssumeRole`).
5. **CloudTrail-disablement and SES-abuse have no published "% across N incidents" figure** —
   they're technique-validated (named in incidents) but not aggregate-quantified.

**Telemetry caveats on the "unavoidable API" claim:** the *management-plane* calls above are
unavoidable and logged. Some *data-plane* activity is not — **S3 data events (`GetObject`) are
off by default** (noted by Sysdig, Invictus, AWS), SCARLETEEL hid exfil with `--endpoint-url`,
and Codefinger's SSE-C key is only logged as a non-reversible HMAC. Where a chokepoint depends
on data-plane logging, that dependency is stated in the entry's `observability` block.

---

## Sources

1. Permiso Security — "LUCR-3: Scattered Spider Getting SaaS-y in the Cloud," 2023-09-20 — https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
2. CrowdStrike — "2025 Global Threat Report" (findings) — https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-global-threat-report-findings/
3. CISA/FBI — "Androxgh0st Malware" AA24-016A, 2024-01-16 — https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a
4. CISA/FBI — "Scattered Spider" AA23-320a, 2023-11-16 (upd. 2025) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
5. CrowdStrike — "Scattered Spider Escalates Attacks," 2025-07-02 — https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/
6. Sysdig — "SCARLETEEL: … Terraform, Kubernetes, and AWS for data theft," 2023-02-28 — https://www.sysdig.com/blog/cloud-breach-terraform-data-theft
7. Sysdig — "SCARLETEEL 2.0: Fargate, Kubernetes, and Crypto," 2023-07-11 — https://www.sysdig.com/blog/scarleteel-2-0
8. Sysdig — "AMBERSQUID Cloud-Native Cryptojacking," 2023-09-18 — https://www.sysdig.com/blog/ambersquid
9. Unit 42 — "CloudKeys in the Air: … Exposed IAM Keys (EleKtra-Leak)," 2023-10-30 — https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/
10. Unit 42 — "TeamTNT Actively Enumerating Cloud Environments," 2021-06-04 — https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/
11. Unit 42 — "Leaked Environment Variables Allow Large-Scale Extortion," 2024-08-15 — https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/
12. Unit 42 — "2025 Cloud Security Alert Trends," 2025 — https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/
13. Wiz — "Inside a Cloud Email Service Takeover," 2025-09-04 — https://www.wiz.io/blog/wiz-discovers-cloud-email-abuse-campaign
14. Datadog Security Labs — "The Attacker doth persist too much, methinks," 2025-05-13 — https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/
15. Datadog Security Labs — Cloud Security Atlas: "Using Amazon SES to send spam," 2024-11-29 — https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/using-ses-to-send-spam/
16. Datadog — "State of Cloud Security 2024," 2024-10 — https://www.datadoghq.com/about/latest-news/press-releases/datadogs-state-of-cloud-security-2024-finds-room-for-improvement-in-the-use-of-long-lived-credentials-across-all-major-clouds/
17. Permiso — "SES-pionage: Detecting SES Abuse," 2023-01-12 — https://permiso.io/blog/s/aws-ses-pionage-detecting-ses-abuse/
18. Halcyon — "Abusing AWS Native Services: Ransomware Encrypting S3 with SSE-C (Codefinger)," 2025-01-13 — https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c
19. Invictus IR — "Ransomware in the cloud" — https://www.invictus-ir.com/news/ransomware-in-the-cloud
20. AWS Security Blog — "GuardDuty ETD uncovers cryptomining campaign on EC2 and ECS," 2025-12-16 — https://aws.amazon.com/blogs/security/cryptomining-campaign-targeting-amazon-ec2-and-amazon-ecs/
21. AWS Security Blog — "Anatomy of a ransomware event targeting data in Amazon S3" — https://aws.amazon.com/blogs/security/anatomy-of-a-ransomware-event-targeting-data-in-amazon-s3/
22. Mandiant / Google Cloud — "M-Trends 2025" — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/
23. Microsoft MSTIC — "Storm-0501's evolving techniques lead to cloud-based ransomware" (Azure), 2025-08-27 — https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
24. Google Cloud — "Threat Horizons Report" (weak-credential initial-access figure via secondary reporting: Cybersecurity Dive) — https://cloud.google.com/security/resources/cloud-threat-horizons

*Load-bearing citations (Codefinger SSE-C mechanism, CrowdStrike 35%/26%/50% figures,
Permiso LUCR-3 eventNames) were re-verified against the source page on 2026-07-03. Figures are
transcribed as published; where a primary PDF could not be parsed the figure is flagged as
secondary-sourced above.*
