# Azure emulation — Activity Log

Lab-only commands to fire each Azure chokepoint. Use a throwaway subscription/resource group
(`az account set -s <sandbox>`). Scratch resources:

```bash
RG=cp-test-rg; az group create -n $RG -l eastus
SUB=$(az account show --query id -o tsv)
```

| Chokepoint | Command | Cleanup / note |
|---|---|---|
| role-assignment-created | `az role assignment create --assignee <object-id> --role Owner --scope /subscriptions/$SUB/resourceGroups/$RG` | `az role assignment delete ...` |
| custom-role-definition-created | `az role definition create --role-definition @role.json` (Actions include `Microsoft.Authorization/*/write`) | `az role definition delete` |
| elevate-access-all-subscriptions | ☢️ **high-impact, tenant-wide** — `az rest --method post --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"` | reverse by removing the root-scope UAA assignment; **only in a throwaway tenant** |
| storage-account-key-regenerated | `az storage account keys renew --account-name <acct> -g $RG --key primary` | key rotates (invalidates old); expected in lab |
| key-vault-access-policy-write | `az keyvault set-policy --name <kv> --object-id <id> --secret-permissions get list` | `az keyvault delete-policy` |
| diagnostic-settings-deleted | `az monitor diagnostic-settings delete --name <ds> --resource <resource-id>` | recreate the diagnostic setting |
| nsg-rule-opened-to-internet | `az network nsg rule create --nsg-name <nsg> -g $RG -n cp-open --priority 100 --access Allow --direction Inbound --source-address-prefixes '*' --destination-port-ranges 22 3389` | `az network nsg rule delete` |
| defender-for-cloud-disabled | `az security pricing create -n VirtualMachines --tier Free` | set `--tier Standard` to restore |
| vm-run-command | 💲 `az vm run-command invoke -g $RG -n <vm> --command-id RunShellScript --scripts "id"` | needs a running test VM |
| app-service-kudu-command | `az functionapp keys list -g $RG -n <fn>` · (Kudu) POST to `https://<app>.scm.azurewebsites.net/api/command` | read/exec on a test app only |
| managed-disk-exported-sas | `az disk grant-access -g $RG -n <disk> --duration-in-seconds 3600 --access-level Read` | `az disk revoke-access -g $RG -n <disk>` |
| backup-recovery-destruction | `az snapshot delete -g $RG -n <snap>` · `az lock delete --name <lock> --resource-group $RG` | destructive — throwaway resources only |
| key-vault-secret-read `[blind]` | `az keyvault secret show --vault-name <kv> --name <secret>` | requires **Key Vault AuditEvent diagnostic logging** → Log Analytics |
| storage-bulk-blob-read `[blind]` | `az storage blob download --account-name <acct> -c <container> -n <blob> -f ./out` (repeat) | requires **Storage StorageRead diagnostic logging** |
