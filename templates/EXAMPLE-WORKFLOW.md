# Example workflow — adding a new chokepoint end-to-end

A worked example of contributing one new chokepoint, mirroring how the entries in this repo
were built.

1. **Pick the invariant.** Ask the six questions (README → The Framework). What operation can
   the attacker *not* avoid? Example (GCP): to steal a secret you must call `AccessSecretVersion`.
2. **Confirm observability (Q5).** Which audit log carries it, and is it on by default? For
   `AccessSecretVersion` the answer is *Data Access logs — OFF by default*, so
   `observability.status: INGEST_GAP`. Record the enablement dependency in `notes`.
3. **Write the entry.** Copy `chokepoint-template.yml` to
   `chokepoints/<cloud>/<tactic>/<slug>.yml`, fill every field, set `validation_tier` from the
   threat intel (see `trends/<cloud>-chokepoint-convergence.md`).
4. **Write the three detection tiers.** research (every occurrence) → hunt (+ narrowing
   invariant) → analyst (+ allowlists from your own baseline, carries `severity`).
5. **Add a portable Sigma rule** under `sigma-rules/<cloud>_<slug>.yml` for the analyst tier.
6. **(Optional) emulation.** Add a safe, lab-only command under `emulation/` to generate the
   telemetry.
7. **Qualification gate.** *If the attacker switches tools tomorrow, does it still fire?* If it
   keys on a tool/UA/IP, move the anchor back to the invariant.
8. **Add to the Chokepoint Index** in the README.
