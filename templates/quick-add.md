# Quick-add: a tool variant to an existing chokepoint

Use this when you've seen a *new tool or technique variant* that hits an **already-documented
chokepoint** — you don't need a new entry, just to record the variation.

1. Find the chokepoint entry under `chokepoints/<cloud>/<tactic>/<slug>.yml`.
2. Add the variant to `chokepoint.variations` (a new API path to the same outcome) and/or
   `actors` (if a named actor was documented using it).
3. If it introduces a *new* observable operation, add it to `chokepoint.operations`.
4. If it strengthens the evidence, bump `validation_tier` and add the source to `references`.
5. Do **not** create a duplicate entry — the whole point of a chokepoint is that tool variants
   collapse onto the same invariant.

Example: a new offensive tool that escalates via `CreatePolicyVersion` is just another
`tool_variation` under `chokepoints/aws/privilege-escalation/iam-create-policy-version.yml` —
the detection already fires on it.
