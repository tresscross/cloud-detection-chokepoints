# Emulation

Safe, **lab-only** commands to generate the CloudTrail telemetry each chokepoint depends on,
so you can validate a detection fires before trusting it in production.

> ⚠️ Run these ONLY in an isolated test/sandbox account you own, with resources you created
> for the test, and tear them down afterward. Never against production or shared accounts.

Two approaches:

1. **`stratus-red-team`** ([DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team))
   — purpose-built, self-cleaning cloud attack emulation. Preferred where a TTP exists.
2. **Raw `aws-cli`** — minimal one-liners to emit a single chokepoint event.

## Chokepoint → emulation

| Chokepoint | stratus-red-team TTP (if any) | Minimal aws-cli (lab only) |
|---|---|---|
| `iam-create-policy-version` | — | `aws iam create-policy-version --policy-arn <test-policy-arn> --policy-document file://wildcard.json --set-as-default` |
| `iam-privileged-policy-attach` | `aws.privilege-escalation.iam-*` | `aws iam attach-role-policy --role-name <test-role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` |
| `iam-role-trust-external-principal` | — | `aws iam update-assume-role-policy --role-name <test-role> --policy-document file://trust-external.json` (Principal AWS = a second test account you own) |
| `iam-federation-idp-created` | — | `aws iam create-saml-provider --name test-idp --saml-metadata-document file://metadata.xml` |
| `kms-key-sabotage` | — | `aws kms schedule-key-deletion --key-id <test-key> --pending-window-in-days 7` (then `cancel-key-deletion` to clean up) |
| `cloudtrail-config-tampering` | `aws.defense-evasion.cloudtrail-stop` | `aws cloudtrail stop-logging --name <test-trail>` (restart after) |
| `secrets-manager-mass-read` | `aws.credential-access.secretsmanager-retrieve-secrets` | `aws secretsmanager get-secret-value --secret-id <test-secret>` |
| `iam-enumeration-burst` | `aws.discovery.*` | loop: `aws iam list-users; list-roles; list-policies; get-account-authorization-details; list-access-keys; get-account-summary` in quick succession |
| `ebs-snapshot-ami-shared-external` | `aws.exfiltration.ec2-share-ebs-snapshot` | `aws ec2 modify-snapshot-attribute --snapshot-id <test-snap> --attribute createVolumePermission --operation-type add --user-ids <second-account-you-own>` |
| `sts-cross-account-new-principal` | — | from a second test account: `aws sts assume-role --role-arn arn:aws:iam::<lab-acct>:role/<test-role> --role-session-name test` |
| `console-login-anomaly` | — | sign in to the console as a test IAM user with MFA disabled (test account) |
| `ses-sending-identity-abuse` | — | `aws ses verify-domain-identity --domain test.example.com` (sandbox) |
| `eventbridge-cross-account-target` | — | `aws events put-targets --rule <test-rule> --targets 'Id=1,Arn=arn:aws:lambda:us-east-1:<second-account-you-own>:function:test'` |

## Validation loop

For each detection:

1. Baseline the Research-tier query — note existing volume.
2. Run the emulation command once.
3. Confirm the event appears (`eventName`, expected `requestParameters`).
4. Confirm the Hunt/Analyst tier fires on it and nothing else.
5. Tear down the test resources.
