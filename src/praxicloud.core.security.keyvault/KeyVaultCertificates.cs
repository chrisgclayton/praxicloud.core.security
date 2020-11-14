// Copyright (c) Christopher Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    using System.Diagnostics;
    using System.Threading;
    using System.Threading.Tasks;
    using Azure.Core;
    using Azure.Security.KeyVault.Certificates;
    #endregion

    /// <summary>
    /// The Key Vault interop instance for certificates
    /// </summary>
    public sealed class KeyVaultCertificates
    {
        #region Constructor
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="keyVault">The key vault URI</param>
        /// <param name="credential">Oauth token credentials</param>
        /// <param name="options">The options used to access the certificates</param>
        public KeyVaultCertificates(Uri keyVault, TokenCredential credential, CertificateClientOptions options)
        {
            Guard.NotNull(nameof(credential), credential);
            Guard.NotNull(nameof(options), options);
            Guard.NotNull(nameof(keyVault), keyVault);

            Client = new CertificateClient(keyVault, credential, options);
        }
        #endregion
        #region Properties
        /// <summary>
        /// The Key Vault certificate client
        /// </summary>
        public CertificateClient Client { get; }
        #endregion
        #region Constructors
        /// <summary>
        /// Retrieves the Key Vault certificate options
        /// </summary>
        /// <param name="version">The version of the key vault API to use</param>
        /// <returns>An instance of Key Vault options</returns>
        public static CertificateClientOptions GetOptions(CertificateClientOptions.ServiceVersion? version = null)
        {
            return version.HasValue ? new CertificateClientOptions(version.Value) : new CertificateClientOptions();
        }
        #endregion
        #region Methods
        /// <summary>
        /// Retrieves the certificate based on the name and version if provided
        /// </summary>
        /// <param name="name">The name of the certificate to retrieve</param>
        /// <param name="version">The certificate version or null to get the latest</param>
        /// <param name="cancellationToken">A token to monitor for abort requests</param>
        /// <returns>The response from the query</returns>
        public async Task<KeyVaultCertificateResponse> GetAsync(string name, string version = null, CancellationToken cancellationToken = default)
        {
            Guard.NotNullOrWhitespace(nameof(name), name);

            KeyVaultCertificateResponse response;

            try
            {
                var watch = Stopwatch.StartNew();

                if (string.IsNullOrWhiteSpace(version))
                {
                    var queryResponse = await Client.GetCertificateAsync(name, cancellationToken).ConfigureAwait(false);
                                      
                    using (var raw = queryResponse.GetRawResponse())
                    {
                        response = new KeyVaultCertificateResponse(queryResponse.Value, raw.Status, watch.ElapsedMilliseconds);
                    }
                }
                else
                {
                    var queryResponse = await Client.GetCertificateVersionAsync(name, version, cancellationToken).ConfigureAwait(false);

                    using (var raw = queryResponse.GetRawResponse())
                    {
                        response = new KeyVaultCertificateResponse(queryResponse.Value, raw.Status, watch.ElapsedMilliseconds);
                    }
                }

                watch.Stop();

            }
            catch (Exception e)
            {
                response = new KeyVaultCertificateResponse(name, version, e);
            }

            return response;
        }

        /// <summary>
        /// Configures the retries on an options instance
        /// </summary>
        /// <param name="options">The options instance</param>
        /// <param name="mode">The retry mode</param>
        /// <param name="maximumRetries">The maximum retries to be performed</param>
        /// <param name="delay">The delay before invoking the first retry</param>
        /// <param name="maximumDelay">The maximum delay allowed between retries</param>
        /// <param name="networkTimeout">The network timeout for a single operation</param>
        public static void ConfigureRetries(CertificateClientOptions options, RetryMode mode, int maximumRetries, TimeSpan delay, TimeSpan maximumDelay, TimeSpan networkTimeout)
        {
            options.Retry.Delay = delay;
            options.Retry.MaxDelay = maximumDelay;
            options.Retry.MaxRetries = maximumRetries;
            options.Retry.NetworkTimeout = networkTimeout;
            options.Retry.Mode = mode;
        }

        /// <summary>
        /// Configures the diagnostics information associated with a credential option
        /// </summary>
        /// <param name="options">The option instance</param>
        /// <param name="applicationId">The application id</param>
        /// <param name="isDistributedTracingEnabled">True if distributed tracing is in use</param>
        /// <param name="isLoggingContentEnabled">True if logging of content is enabled</param>
        /// <param name="isLoggingEnabled">True if logging is enabled</param>
        /// <param name="isTelemetryEnabled">True if telemetry is enabled</param>
        /// <param name="loggingContentSizeLimit">The maximum size of the content being logged</param>
        public static void ConfigureDiagnostics(CertificateClientOptions options, string applicationId, bool isDistributedTracingEnabled, bool isLoggingContentEnabled, bool isLoggingEnabled, bool isTelemetryEnabled, int loggingContentSizeLimit)
        {
            options.Diagnostics.ApplicationId = applicationId;
            options.Diagnostics.IsDistributedTracingEnabled = isDistributedTracingEnabled;
            options.Diagnostics.IsLoggingContentEnabled = isLoggingContentEnabled;
            options.Diagnostics.IsLoggingEnabled = isLoggingEnabled;
            options.Diagnostics.IsTelemetryEnabled = isTelemetryEnabled;
            options.Diagnostics.LoggedContentSizeLimit = loggingContentSizeLimit;
        }
        #endregion
    }
}
