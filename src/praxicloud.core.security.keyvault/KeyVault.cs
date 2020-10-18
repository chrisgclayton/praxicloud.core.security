// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    using Azure.Core;
    using Azure.Security.KeyVault.Certificates;
    using Azure.Security.KeyVault.Keys;
    using Azure.Security.KeyVault.Secrets;
    #endregion

    /// <summary>
    /// The key vault entry point
    /// </summary>
    public sealed class KeyVault
    {
        #region Constants
        /// <summary>
        /// The default suffix for key vault in the public cloud
        /// </summary>
        public const string DefaultSuffix = @"vault.azure.net";

        /// <summary>
        /// The separator between subdomains in the fully qualified name
        /// </summary>
        public const string SubdomainSeparator = @".";

        /// <summary>
        /// The default diagnostics application id
        /// </summary>
        public const string DefaultApplicationId = @"KeyVaultInterop";
        #endregion
        #region Variables
        /// <summary>
        /// The default network timeout
        /// </summary>
        public static readonly TimeSpan DefaultNetworkTimeout = TimeSpan.FromSeconds(5);

        /// <summary>
        /// The default delay between retries
        /// </summary>
        public static readonly TimeSpan DefaultDelay = TimeSpan.FromSeconds(2);

        /// <summary>
        /// The default maximum delay between retries
        /// </summary>
        public static readonly TimeSpan DefaultMaximumDelay = TimeSpan.FromSeconds(10);

        /// <summary>
        /// The default maximum retry count
        /// </summary>
        public static readonly int DefaultMaximumRetries = 3;

        /// <summary>
        /// The credential used to retrieve a token
        /// </summary>
        private readonly TokenCredential _credential;
        #endregion
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="vaultName">The name of the Key Vault</param>
        /// <param name="credential">The Oauth token provider credential</param>
        /// <param name="maximumRetries">The maximum number of retries for operations</param>
        /// <param name="delay">The delay between retries</param>
        /// <param name="maximumDelay">The maximum delay between retries</param>
        /// <param name="networkTimeout">The network timeout on operations</param>
        public KeyVault(string vaultName, TokenCredential credential, int? maximumRetries, TimeSpan? delay, TimeSpan? maximumDelay, TimeSpan? networkTimeout)
        {
            Guard.NotNull(nameof(credential), credential);
            Guard.NotNullOrWhitespace(nameof(vaultName), vaultName);
            FullyQualifiedName = GetFullyQualifiedKeyVaultName(vaultName);
            Guard.NotNullOrWhitespace(nameof(vaultName), FullyQualifiedName);

            Name = GetBaseKeyVaultName(FullyQualifiedName);
            Uri = new Uri($"https://{FullyQualifiedName}");

            _credential = credential;
            MaximumRetries = maximumRetries.HasValue && maximumRetries.Value >= 0 ? maximumRetries.Value : DefaultMaximumRetries;
            Delay = delay.HasValue && delay.Value >= TimeSpan.Zero ? delay.Value : DefaultDelay;
            MaximumDelay = maximumDelay.HasValue && maximumDelay.Value >= Delay ? maximumDelay.Value : (DefaultMaximumDelay >= Delay ? DefaultMaximumDelay : Delay);
            NetworkTimeout = networkTimeout.HasValue && networkTimeout.Value >= TimeSpan.Zero ? networkTimeout.Value : DefaultNetworkTimeout;
        }
        #endregion
        #region Properties
        /// <summary>
        /// The Key Vault's name
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The Key Vault's fully qualified name
        /// </summary>
        public string FullyQualifiedName { get; }

        /// <summary>
        /// The Key Vault's Uri
        /// </summary>
        public Uri Uri { get; }

        /// <summary>
        /// Maximum number of retries
        /// </summary>
        public int MaximumRetries { get; } 
        
        /// <summary>
        /// Delay between retries
        /// </summary>
        public TimeSpan Delay { get; }
        
        /// <summary>
        /// Maximum delay between retries
        /// </summary>
        public TimeSpan MaximumDelay { get; }
        
        /// <summary>
        /// The network timeout for operations
        /// </summary>
        public TimeSpan NetworkTimeout { get; }

        /// <summary>
        /// True to enable diagnostics on all created secrets etc.
        /// </summary>
        public bool EnableDiagnostics { get; set; }

        /// <summary>
        /// The application id for diagnostics
        /// </summary>
        public string DiagnosticsApplicationId { get; set; }
        #endregion
        #region Methods
        /// <summary>
        /// Retrieves a new instance of a key vault secret
        /// </summary>
        /// <param name="version">The version of the client to use</param>
        /// <returns>A key vault secret instance</returns>
        public KeyVaultSecrets GetSecretsClient(SecretClientOptions.ServiceVersion version = SecretClientOptions.ServiceVersion.V7_1)
        {
            var options = KeyVaultSecrets.GetOptions(version);

            KeyVaultSecrets.ConfigureRetries(options, RetryMode.Exponential, MaximumRetries, Delay, MaximumDelay, NetworkTimeout);
            
            if(EnableDiagnostics)
            {
                KeyVaultSecrets.ConfigureDiagnostics(options, (string.IsNullOrWhiteSpace(DiagnosticsApplicationId) ? DefaultApplicationId : DiagnosticsApplicationId), true, true, true, true, 4096);
            }

            return new KeyVaultSecrets(Uri, _credential, options);
        }

        /// <summary>
        /// Retrieves a new instance of a key vault certificate
        /// </summary>
        /// <param name="version">The version of the client to use</param>
        /// <returns>A key vault certificate instance</returns>
        public KeyVaultCertificates GetCertificatesClient(CertificateClientOptions.ServiceVersion version = CertificateClientOptions.ServiceVersion.V7_1)
        {
            var options = KeyVaultCertificates.GetOptions(version);

            KeyVaultCertificates.ConfigureRetries(options, RetryMode.Exponential, MaximumRetries, Delay, MaximumDelay, NetworkTimeout);

            if (EnableDiagnostics)
            {
                KeyVaultCertificates.ConfigureDiagnostics(options, (string.IsNullOrWhiteSpace(DiagnosticsApplicationId) ? DefaultApplicationId : DiagnosticsApplicationId), true, true, true, true, 4096);
            }

            return new KeyVaultCertificates(Uri, _credential, options);
        }

        /// <summary>
        /// Retrieves a new instance of a key vault key
        /// </summary>
        /// <param name="version">The version of the client to use</param>
        /// <returns>A key vault key instance</returns>
        public KeyVaultKeys GetKeysClient(KeyClientOptions.ServiceVersion version = KeyClientOptions.ServiceVersion.V7_1)
        {
            var options = KeyVaultKeys.GetOptions(version);

            KeyVaultKeys.ConfigureRetries(options, RetryMode.Exponential, MaximumRetries, Delay, MaximumDelay, NetworkTimeout);

            if (EnableDiagnostics)
            {
                KeyVaultKeys.ConfigureDiagnostics(options, (string.IsNullOrWhiteSpace(DiagnosticsApplicationId) ? DefaultApplicationId : DiagnosticsApplicationId), true, true, true, true, 4096);
            }

            return new KeyVaultKeys(Uri, _credential, options);
        }

        /// <summary>
        /// Cleans the vault name and returns the fully qualified name variant or an empty string if it is not valid
        /// </summary>
        /// <param name="vaultName">The vault name</param>
        /// <returns>The fully qualified vault name</returns>
        public static string GetFullyQualifiedKeyVaultName(string vaultName)
        {
            Guard.NotNullOrWhitespace(nameof(vaultName), vaultName);

            var cleanName = RemoveOuterSubdomainSeperators(vaultName);
            
            return string.IsNullOrWhiteSpace(cleanName) || cleanName.IndexOf(".") >= 0 ? cleanName : $"{ cleanName }.{ DefaultSuffix }";
        }

        /// <summary>
        /// Cleans the vault name and returns the non qualified name
        /// </summary>
        /// <param name="vaultName">The name of the vault</param>
        /// <returns>A clean version of the base name</returns>
        public static string GetBaseKeyVaultName(string vaultName)
        {
            Guard.NotNullOrWhitespace(nameof(vaultName), vaultName);

            var cleanName = RemoveOuterSubdomainSeperators(vaultName);
            var subdomainIndex = cleanName.IndexOf(SubdomainSeparator);

            return subdomainIndex > 0 ? cleanName.Substring(0, subdomainIndex) : cleanName;
        }

        /// <summary>
        /// Removes subdomain seperators and trims the domain string to determine the fully qualified name
        /// </summary>
        /// <param name="domainString">The domain string to be cleaned</param>
        /// <returns>The clean string</returns>
        private static string RemoveOuterSubdomainSeperators(string domainString)
        {
            var domainStringSpan = domainString.AsSpan().Trim();

            while (domainStringSpan.StartsWith(SubdomainSeparator) && domainStringSpan.Length > 0)
            {
                domainStringSpan = domainStringSpan.Slice(1, domainStringSpan.Length - 1);
            }

            while (domainStringSpan.EndsWith(SubdomainSeparator) && domainStringSpan.Length > 0)
            {
                domainStringSpan = domainStringSpan.Slice(0, domainStringSpan.Length - 1);
            }

            var value = domainStringSpan.ToString();

            return string.Equals(value, SubdomainSeparator, StringComparison.Ordinal) && domainStringSpan.Length == 0 ? string.Empty : domainStringSpan.ToString();
        }
        #endregion
    }
}
