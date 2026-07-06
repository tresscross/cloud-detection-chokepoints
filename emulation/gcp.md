# GCP emulation — Cloud Audit Logs

Lab-only commands to fire each GCP chokepoint. Use a throwaway project (`gcloud config set
project <sandbox>`). Scratch resources:

```bash
gcloud iam service-accounts create cp-test --display-name "chokepoint test"
SA="cp-test@$(gcloud config get-value project).iam.gserviceaccount.com"
```

| Chokepoint | Command | stratus TTP | Cleanup / note |
|---|---|---|---|
| service-account-key-created | `gcloud iam service-accounts keys create key.json --iam-account $SA` | `gcp.persistence.create-admin-service-account` (adjacent) | delete the key + `rm key.json` |
| service-account-created-and-keyed | `gcloud iam service-accounts create cp-test2` then the key command above | `gcp.persistence.create-admin-service-account` | `gcloud iam service-accounts delete` |
| setiampolicy-privileged-grant | `gcloud projects add-iam-policy-binding <proj> --member="user:you@example.com" --role="roles/owner"` | `gcp.persistence.invite-external-user` (adjacent) | `remove-iam-policy-binding` |
| service-account-tokencreator-grant | `gcloud iam service-accounts add-iam-policy-binding $SA --member="user:you@example.com" --role="roles/iam.serviceAccountTokenCreator"` | `gcp.privilege-escalation.impersonate-service-accounts` | `remove-iam-policy-binding` |
| privileged-service-account-attach / instance-startup-script-attached-sa | 💲 `gcloud compute instances create cp-vm --service-account=$SA --scopes=cloud-platform --metadata=startup-script='#! /bin/bash\nid'` | — | `gcloud compute instances delete cp-vm` |
| actas-bypass-deployment-agent | `gcloud deployment-manager deployments create cp-dep --config config.yaml` · `gcloud builds submit --config cloudbuild.yaml` | — | delete the deployment/build |
| custom-role-privilege-add | `gcloud iam roles create cpRole --project=<proj> --permissions=resourcemanager.projects.setIamPolicy` | — | `gcloud iam roles delete` |
| org-policy-constraint-weakened | `gcloud resource-manager org-policies disable-enforce <constraint> --project=<proj>` | — | re-enable the constraint |
| logging-sink-deleted-or-disabled | `gcloud logging sinks update <sink> --disabled` · `gcloud logging sinks delete <sink>` | `gcp.defense-evasion.*` | recreate/enable the sink |
| log-bucket-deleted-or-retention-reduced | `gcloud logging buckets update <bucket> --location=global --retention-days=1` | — | restore retention |
| firewall-opened-to-world | `gcloud compute firewall-rules create cp-open --allow=tcp:22 --source-ranges=0.0.0.0/0` | `gcp.defense-evasion.*` | `gcloud compute firewall-rules delete cp-open` |
| network-telemetry-disabled | `gcloud compute networks subnets update <subnet> --region=<r> --no-enable-flow-logs` | — | re-enable flow logs |
| gcs-bucket-made-public | `gcloud storage buckets add-iam-policy-binding gs://<test> --member=allUsers --role=roles/storage.objectViewer` | `gcp.exfiltration.*` | remove the allUsers binding |
| cryptomining-compute-hijack | 💲 `gcloud compute instances create cp-miner --machine-type=n2-standard-8 --zone=<z>` (or `--dry-run`-style: add `--format=disable` on a describe) | — | delete immediately; prefer a tiny type in lab |
| workload-identity-federation-added | `gcloud iam workload-identity-pools create cp-pool --location=global` · `... providers create-oidc` | — | delete the pool |
| ssh-key-added-to-metadata | `gcloud compute instances add-metadata cp-vm --metadata=ssh-keys="test:ssh-rsa AAAA..."` | — | `remove-metadata` |
| serverless-scheduled-backdoor | `gcloud functions deploy cp-fn --runtime=python312 --trigger-http --allow-unauthenticated --entry-point=main` · `gcloud scheduler jobs create http cp-job --schedule="* * * * *" --uri=<url>` | — | delete the function/job |
| valid-account-control-plane | any authenticated `gcloud` call from a new principal / unusual IP after `gcloud auth login` | — | control-plane sign-in signal |
| sa-impersonation-token `[blind]` | `gcloud auth print-access-token --impersonate-service-account=$SA` | `gcp.privilege-escalation.impersonate-service-accounts` | requires **DATA_READ on iamcredentials** |
| secret-manager-access `[blind]` | `gcloud secrets versions access latest --secret=<test-secret>` | `gcp.credential-access.secretmanager-retrieve-secrets` | requires **DATA_READ on secretmanager** |
| iam-permission-bruteforce `[blind]` | `gcloud projects test-iam-permissions <proj> --permissions=resourcemanager.projects.setIamPolicy,...` | — | requires **ADMIN_READ on resourcemanager/iam** |
| cloud-asset-inventory-enumeration `[blind]` | `gcloud asset search-all-resources --scope=projects/<proj>` | — | requires **ADMIN_READ on cloudasset** |
| resource-enumeration `[blind]` | `gcloud compute instances list; gcloud storage buckets list; gcloud iam service-accounts list` | — | requires **DATA_READ** per service |
| gcs-bulk-object-read `[blind]` | `gcloud storage cp gs://<test>/<obj> .` (repeat) | `gcp.exfiltration.exfiltrate-*` | requires **DATA_READ on storage** |
| gcs-data-destruction-ransomware | `gcloud storage rm gs://<test>/<obj>` (mass) | — | destructive — throwaway objects only |
