# PraxiCloud Core Security KeyVault
PraxiCloud Libraries are a set of common utilities and tools for general software development that simplify common development efforts for software development. The core KeyVault library contains basic utilities and functions used to integrate with Azure Key Vault. 



# Installing via NuGet

Install-Package PraxiCloud-Core-Security-KeyVault



# Key Vault



## Key Types and Interfaces

|Class| Description | Notes |
| ------------- | ------------- | ------------- |
|**KeyVault**|Operates as the entry point to create certificate, secret and key clients from the same account details. Additional methods provide ability to adjust naming between fully qualified and friendly subdomains.<br />***GetSecretsClient*** creates a KeyVault secrets client associated with the current account.<br />***GetKeysClient*** creates a KeyVault keys client associated with the current account.<br />***GetCertificatesClient*** creates a KeyVault certificate client associated with the current account. <br />***GetFullyQualifiedKeyVaultName*** retrieves the fully qualified KeyVault name based on the friendly name, assuming the default public region.<br />***GetBaseKeyVaultName*** retrieves the user friendly name from the fully qualified KeyVault name.| Typically this is the entry point to start integrating from. |
|**KeyVaultCertificates**|Used to retrieve X509 certificates from the KeyVault.<br />***GetAsync*** retrieves a certificate from the KeyVault. The certificate's associated secret is also accessed providing retrieval for the private key elements.|  |
|**KeyVaultSecrets**|Used to retrieve secrets from the KeyVault.<br />***GetAsync*** retrieves a secret from the key vault.<br />***GetCertificateAsync*** retrieves a secret that stored a certificate using the none standard techniques.| For certificate retrieval it is best to store the certificates as certificates instead of secrets within the KeyVault. For this use the KeyVaultCertificates client for this instead. |
|**KeyVaultKeys**|Used to retrieve keys from the KeyVault.<br />***GetAsync*** retrieves a key from the KeyVault.| This client is not current implementing decryption and encryption operations for the keys. If using this for encryption and decryption it is recommended to extend the client to support this. |

## Sample Usage

### Get Secret Using Client Secret

```csharp
public async Task<SecureString> GetSecretAsync(string keyVault, string tenantId, string clientId, string clientSecret, string secretName)
{
    const string VaultName = "fakevault1";
    const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
    const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
    const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

    var tokenProvider = AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret);
    var vault = new KeyVault(VaultName, tokenProvider, 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
    var client = vault.GetSecretsClient();

    var response = await client.GetAsync("mysecret").ConfigureAwait(false);

    return response.Value;
}
```

### Get Secret Using Managed Identity

```csharp
public async Task<SecureString> GetSecretAsync(string keyVault, string tenantId, string clientId, string clientSecret, string secretName)
{
    const string VaultName = "fakevault1";

    var tokenProvider = AzureOauthTokenAuthentication.GetOauthTokenCredentialFromManagedIdentity();
    var vault = new KeyVault(VaultName, tokenProvider, 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
    var client = vault.GetSecretsClient();

    var response = await client.GetAsync("mysecret").ConfigureAwait(false);

    return response.Value;
}
```

### Get X509 Certificate Using Managed Identity

```csharp
public async Task<X509Certificate2> GetCertificateAsync(string keyVault, string tenantId, string clientId, string clientSecret, string certificateName)
{
    const string VaultName = "fakevault1";

    var tokenProvider = AzureOauthTokenAuthentication.GetOauthTokenCredentialFromManagedIdentity();
    var vault = new KeyVault(VaultName, tokenProvider, 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
    var client = vault.GetCertificatesClient();

    var response = await client.GetAsync("mycertificate").ConfigureAwait(false);

    return new X509Certificate2(response.Value);
}
```

### Get Key Using Managed Identity

```csharp
public async Task<JsonWebKey> GetKeyAsync(string keyVault, string tenantId, string clientId, string clientSecret, string secretName)
{
    const string VaultName = "fakevault1";

    var tokenProvider = AzureOauthTokenAuthentication.GetOauthTokenCredentialFromManagedIdentity();
    var vault = new KeyVault(VaultName, tokenProvider, 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
    var client = vault.GetKeysClient();

    var response = await client.GetAsync("mykey").ConfigureAwait(false);

    return response.Value;
}
```

## Additional Information

For additional information the Visual Studio generated documentation found [here](./documents/praxicloud.core.security.keyvault/praxicloud.core.security.keyvault.xml), can be viewed using your favorite documentation viewer.




