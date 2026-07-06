# Emulation

Safe, **lab-only** commands to generate the telemetry each chokepoint depends on, so you can
validate a detection fires (and tune out the noise) before trusting it in production. These are
the atomic building blocks — one command → one control-plane event → one chokepoint.

> ⚠️ **Lab only.** Run these ONLY in an isolated sandbox account/subscription/project you own,
> against throwaway resources you created for the test, and tear them down afterward. Never run
> them against production or shared environments. A few commands are flagged **💲 cost** (they
> spin up compute) or **☢️ high-impact** (tenant/org-wide) — read the note before running.

## Two approaches

1. **[stratus-red-team](https://github.com/DataDog/stratus-red-team)** — purpose-built,
   self-cleaning cloud attack emulation. Preferred where a matching TTP exists (referenced per
   command below). `stratus detonate <ttp>` then `stratus cleanup <ttp>`.
2. **Native CLI one-liners** — `aws` / `gcloud` / `az`. Minimal commands to emit a single
   chokepoint event when no stratus TTP fits, or when you want precise control.

## Per-cloud command sheets

| Cloud | File | Log source it exercises |
|---|---|---|
| AWS | [`aws.md`](aws.md) | CloudTrail management events |
| GCP | [`gcp.md`](gcp.md) | Cloud Audit Logs (Admin Activity; Data Access where enabled) |
| Azure | [`azure.md`](azure.md) | Activity Log (control-plane; diagnostics where enabled) |

## The validation loop (run per detection)

1. **Baseline** the Research-tier query for the chokepoint — note the existing volume in your lab.
2. **Detonate** the emulation command once (note the timestamp).
3. **Confirm the event lands** — the expected operation (`eventName` / `methodName` /
   `operationName`) with the request parameters the detection keys on.
4. **Confirm the Hunt/Analyst tier fires** on your event and *nothing else* over the window.
5. **Tune** — if it over-fires, that's your allowlist/threshold work; re-run.
6. **Clean up** the test resources.

## `[blind]` chokepoints

The chokepoints marked `[blind]` in the [index](../README.md) (secret reads, bulk object reads,
impersonation, recon) are **read/data-plane** operations that are **off by default**. The
emulation command will run fine, but **no event is produced until you enable the read logging**
first (AWS S3 data events / GCP Data Access logs / Azure resource diagnostics). Enable it, then
emulate, to validate those detections.
