# Sigma rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) detections for the chokepoints in this
repo, using `logsource: {product: aws, service: cloudtrail}`. Convert to your backend with
`sigma convert` (splunk, elastic, sentinel, etc.).

## Notes

- **Analyst-tier precision often needs request-parameter or field-to-field logic that Sigma
  expresses only approximately** (e.g. "wildcard action in the policy document", "target
  account ≠ rule account", "≥6 distinct enum APIs per principal per window"). Where that is
  the case, the Sigma rule implements the **Hunt tier** (the eventName + coarse filter) and
  the chokepoint YAML's `detection.analyst` block describes the precise Analyst logic. Each
  rule notes this in its `description`.
- **Allowlists are environment-specific.** `falsepositives` lists the classes to allowlist
  (scanner roles, IaC deployers, known integrations, operating geos). Build them from your
  own baseline — do not treat the examples as universal.
- Group/aggregate on the **underlying role** (`userIdentity.sessionContext.sessionIssuer.userName`),
  not the per-session ARN, in whatever backend you convert to.
