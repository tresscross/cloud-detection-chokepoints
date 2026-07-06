# Contributing

Thanks for helping grow the AWS chokepoint catalog. This repo values **precision over
volume** — one well-analysed chokepoint with a validated invariant beats ten IOC lists.

## What makes a good chokepoint entry

Before you write anything, answer the six framework questions (see the README). An entry
qualifies only if:

1. It anchors to an **invariant** — a mandatory CloudTrail `eventName` (+ request-parameter
   signal) the attacker cannot avoid, not a tool signature / UA / IP / session name.
2. It **passes the qualification test:** *if the attacker switches tools tomorrow, does the
   detection still fire?*
3. The event is **observable** — it appears in CloudTrail and the discriminating field
   survives a typical parser. Note observability caveats in the `observability` block.
4. It doesn't duplicate an existing entry. If it's a **variation** of one (another API path
   to the same outcome), add it under that entry's `variations`, or cross-link with
   `related`.

## Adding an entry

1. Copy [`templates/chokepoint-template.yml`](templates/chokepoint-template.yml) to
   `chokepoints/<cloud>/<tactic>/<slug>.yml`.
2. Fill every required field (see [`schema/chokepoint-schema.md`](schema/chokepoint-schema.md)).
3. Provide detection logic at all **three tiers** (Research / Hunt / Analyst).
4. Add a portable Sigma rule under `sigma-rules/` for the Analyst tier where practical.
5. If you have a lab, add a safe emulation command under `emulation/`.

## Detection hygiene

- **Never hardcode environment-specific allowlists as if they were universal.** Account IDs,
  role names, scanner identities, and operating geos in Analyst-tier logic are
  **placeholders**. Mark them clearly and instruct users to rebuild from their own baseline.
- **No secrets, no real account IDs, no real IPs, no employee names.** Use the AWS canonical
  example account `123456789012` (and `210987654321` / `999999999999` for "external").
- **Group on the stable identity** — the underlying role
  (`userIdentity.sessionContext.sessionIssuer.userName`), not the per-session ARN, which
  changes every STS session.
- **Baseline volume claims** should say the window they came from and note they are
  environment-dependent.

## Style

- YAML entries validate against `schema/chokepoint-schema.md`.
- Sigma rules follow the [Sigma spec](https://github.com/SigmaHQ/sigma) with
  `logsource: {product: aws, service: cloudtrail}`.
- Keep prose tight and technical. Cite MITRE ATT&CK technique IDs.
