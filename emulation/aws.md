# AWS emulation — CloudTrail

Lab-only commands to fire each AWS chokepoint. Replace `<...>` placeholders with throwaway
resources in a sandbox account. Set up a scratch role/policy/bucket first:

```bash
aws iam create-role --role-name cp-test --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam create-policy --policy-name cp-test-pol --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' > wildcard.json
```

| Chokepoint | Command | stratus TTP | Cleanup / note |
|---|---|---|---|
| iam-create-policy-version | `aws iam create-policy-version --policy-arn <pol-arn> --policy-document file://wildcard.json --set-as-default` | — | `aws iam delete-policy-version` (old versions) |
| iam-inline-policy-self-escalation | `aws iam put-role-policy --role-name cp-test --policy-name esc --policy-document file://wildcard.json` | — | `aws iam delete-role-policy --role-name cp-test --policy-name esc` |
| iam-privileged-policy-attach | `aws iam attach-role-policy --role-name cp-test --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | `aws.privilege-escalation.iam-*` | `aws iam detach-role-policy ...` |
| iam-role-trust-external-principal | `aws iam update-assume-role-policy --role-name cp-test --policy-document file://trust-external.json` (Principal `AWS: arn:aws:iam::<second-acct-you-own>:root`) | — | reset the trust policy |
| iam-federation-idp-created | `aws iam create-saml-provider --name cp-test-idp --saml-metadata-document file://metadata.xml` | — | `aws iam delete-saml-provider --saml-provider-arn <arn>` |
| iam-enumeration-burst | `for c in list-users list-roles list-policies get-account-authorization-details list-access-keys get-account-summary list-groups; do aws iam $c >/dev/null; done` | `aws.discovery.*` | read-only, nothing to clean |
| secrets-manager-mass-read | `aws secretsmanager get-secret-value --secret-id <test-secret>` | `aws.credential-access.secretsmanager-retrieve-secrets` | read-only |
| kms-key-sabotage | `aws kms disable-key --key-id <test-key>` · `aws kms schedule-key-deletion --key-id <test-key> --pending-window-in-days 7` | — | `aws kms enable-key` / `aws kms cancel-key-deletion` |
| cloudtrail-config-tampering | `aws cloudtrail stop-logging --name <test-trail>` | `aws.defense-evasion.cloudtrail-stop` | `aws cloudtrail start-logging --name <test-trail>` |
| sts-cross-account-new-principal | from a second account: `aws sts assume-role --role-arn arn:aws:iam::<lab-acct>:role/<role> --role-session-name cptest` | — | session expires; nothing to clean |
| eventbridge-cross-account-target | `aws events put-targets --rule <test-rule> --targets 'Id=1,Arn=arn:aws:lambda:us-east-1:<second-acct-you-own>:function:test'` | — | `aws events remove-targets` |
| ebs-snapshot-ami-shared-external | `aws ec2 modify-snapshot-attribute --snapshot-id <test-snap> --attribute createVolumePermission --operation-type add --user-ids <second-acct-you-own>` | `aws.exfiltration.ec2-share-ebs-snapshot` | reset with `--operation-type remove` |
| s3-cross-account-replication | `aws s3api put-bucket-replication --bucket <src> --replication-configuration file://repl.json` (dest bucket in another acct) | — | `aws s3api delete-bucket-replication --bucket <src>` |
| s3-made-public | `aws s3api delete-public-access-block --bucket <test>` · `aws s3api put-bucket-acl --bucket <test> --acl public-read` | `aws.exfiltration.s3-*` | re-enable PAB / reset ACL |
| ses-sending-identity-abuse | `aws ses verify-domain-identity --domain test.example.com` · `aws sesv2 put-account-details ...` (sandbox) | — | `aws ses delete-identity` |
| resource-hijack-cryptomining | 💲 `aws ec2 run-instances --image-id <ami> --instance-type g4dn.xlarge --count 1` — **or** dry-run to emit the call without launching: `aws ec2 run-instances --dry-run --instance-type g4dn.xlarge --image-id <ami>` | `aws.impact.*` | terminate immediately; prefer `--dry-run` |
| console-login-anomaly | Sign in to the console as a test IAM user with MFA disabled (emits `ConsoleLogin` `MFAUsed=No`); or from a VPN egress in an unusual country | — | management/org trail must be forwarded |
| s3-bulk-object-read `[blind]` | `aws s3 cp s3://<test>/<obj> .` (repeat for volume) | `aws.exfiltration.s3-*` | requires **S3 data-event logging enabled** on the bucket first |
