# Azure Automated ACME

A very simple way to do ACME in Azure, using Let's Encrypt. Works with Azure Application Gateway and Azure Front Door. 

All it does is use an Azure Function to create CSRs, perform ACME orders, store TLS certificates and create/use the ACME account key for issuing requests to your ACME CA of choice inside Azure KeyVault. It uses a Azure Storage Account Static Website to serve ACME challenge files which are reverse proxied by Azure Application Gateway/Azure Front Door to perform HTTP-01 ACME validation.

# Features

- Strong keysizes for issued certificates (RSA 4096)
- HTTP-01 challenges
- Configures Let's Encrypt to email you with alerts regarding issuance
- Ready for usage with RFC 8657 accounturi pinning, which when used, is critical for preventing malicious actors from misissuing certificates
- Automatically pushes certificates to Azure KeyVault
- Automatically fetches account key from Azure KeyVault
- Automatically generates and places account key in Azure KeyVault if one has not been set
- Automatically registers account key at the CA if account key is unregistered
- Does not expose any user maintained web server, instead relies on Azure Blob Storage Static Websites
- Runs cheap as chips, you pay mere cents per month to Microsoft for running this Azure Function when used in a Flex Consumption App Service Plan
- Fully uses Azure Managed Identity - no manual credential management. ever.
- Very easy to audit. Why should you trust me? Trust yourself instead.
- Minimal maintenance overall
- Only uses the Python standard library, no external libraries
- New private key used upon every renewal
- No BS. If this has even a hint of BS anywhere, it is a bug. File an issue.

# Azure resources shopping list

The list here assumes you will be using dedicated Azure resources for ACME automation. Use dedicated resources to uphold a strong security model. Don't cut corners here.

- Azure KeyVault
   - Must be network accessible by the Azure Application Gateway/Azure Front Door
   - Must be network accessible by the Azure Function
   - Must grant Azure Application Gateway the Azure RBAC role of "Key Vault Secrets User" on the TLS certificate secret
   - Must grant Azure Function the Azure RBAC role of "Key Vault Secrets Officer" on the Azure KeyVault
   - If needing to create the secret in advance of having a TLS certificate there, use the value "placeholder" for the initial creation and ignore value changes
- Azure Storage Account
   - Must be configured with Static Websites support enabled
   - Must have Static Website endpoint network accessible by the Azure Application Gateway/Azure Front Door
   - Must have Static Website endpoint network accessible by the Azure Function
   - Must have Blob Storage endpoint network accessible by the Azure Function
   - Must grant Azure Function the Azure RBAC role of "Storage Blob Data Contributor"
- Azure Application Gateway/Azure Front Door
   - Must use KeyVault reference without a version identifier to the KeyVault secret used for TLS certificates
   - Must serve HTTP traffic on port 80 and HTTPS traffic on port 443
   - Must reverse proxy the Azure Blob Storage Static Site to serve requests on "/.well-known/acme-challenge/*"
   - Must have outbound network access to CRLs for TLS CAs used by Azure Blob Storage (HTTP 80 to crl.microsoft.com and crl3.digicert.com)
- Azure Function
   - Must have outbound network access to your ACME CA of choice (e.g HTTPS 443 to acme-v02.api.letsencrypt.org)
   - Must have the source code from this repo deployed to it
   - Must run on a Flex Consumption App Service Plan, if you enjoy not burning money

# Environment Variables

Sample values are provided below.

- "ACME_BLOB_STORAGE_NAME"   = "your-blob-storage-account-name"
- "ACME_KEYVAULT_NAME"       = "your-keyvault-account-name"
- "ACME_CONTACT_EMAIL"       = "mailto:security@yourdomain.invalid"
- "ACME_DIRECTORY_URL"       = "https://acme-v02.api.letsencrypt.org/directory"
- "ACME_COMMON_NAME"         = "myawesomewebsite.invalid"
- "ACCOUNT_KEY_SECRET_NAME"  = "account-key-secret-name-in-kv"
- "TLS_CERT_SECRET_NAME"     = "tls-cert-secret-name-in-kv"

# DNS configuration of CAA records to significantly improve ACME security

In order to significantly improve overall ACME assurance, you must configure a CAA record for your DNS zone. This can in many cases be a "set it and forget it task". One of very few such tasks in the IT industry.

For example, for my hostname I wish to issue certificates for, subdomain.domain.tld, I could assign a CAA record to either domain.tld, which would impact the entire apex DNS zone and all children, or I could just do it for subdomain.domain.tld.

Here is what the DNS record would look like in BIND format:

```subdomain.domain.tld. 3600 IN CAA 0 issue "letsencrypt.org; validationmethods=http-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1337"```

Note, you would replace the "1337" in the above DNS record, with that of the account ID (not account key) which is stored in Azure KeyVault.

This will do 3 things:

- Prevent other CAs other than Let's Encrypt from issuing TLS certificates for this DNS zone
- Prevent other ACME challenges other than HTTP-01 validation
- Prevent malicious actors from abusing Let's Encrypt using techniques such as BGP and DNS zone hijacking, from issuing certificates, as you have a CAA record pinning the account ID, and the credentials for this account are in your Azure KeyVault

It is strongly reccomended to also deploy DNSSEC, as this will further improve resilience of DNS queries performed by the CA when doing ACME challenges, irrespective of challenge type. Though, the CA/Browser forum doesn't currently mandate this for CA's.
