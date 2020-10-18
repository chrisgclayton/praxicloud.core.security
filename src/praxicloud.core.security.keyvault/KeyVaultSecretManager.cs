// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Azure.Core;
    using Azure.Security.KeyVault.Certificates;
    using Azure.Security.KeyVault.Secrets;
    using Newtonsoft.Json;
    using Nito.AsyncEx;
    #endregion

    /// <summary>
    /// A secret manager implementation that is backed by a key vault store
    /// </summary>
    public sealed class KeyVaultSecretManager : ISecretManager
    {
        #region Variables
        /// <summary>
        /// The Key Vault instance used to retrieve the secret, certificate and key client
        /// </summary>
        private readonly KeyVault _keyVault;

        /// <summary>
        /// Key vault secrets client 
        /// </summary>
        private KeyVaultSecrets _secrets = null;

        /// <summary>
        /// Key vault certificates client 
        /// </summary>
        private KeyVaultCertificates _certificates = null;

        /// <summary>
        /// An asynchronous lock that can be used to control access to client creation
        /// </summary>
        private readonly AsyncLock _control = new AsyncLock();
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
        public KeyVaultSecretManager(string vaultName, TokenCredential credential, int? maximumRetries, TimeSpan? delay, TimeSpan? maximumDelay, TimeSpan? networkTimeout)
        {
            Guard.NotNull(nameof(credential), credential);
            Guard.NotNullOrWhitespace(nameof(vaultName), vaultName);

            _keyVault = new KeyVault(vaultName, credential, maximumRetries, delay, maximumDelay, networkTimeout);
        }
        #endregion
        #region Methods
        /// <inheritdoc />
        public async Task<SecretStoreResponse<X509Certificate2>> GetCertificateAsync(string certificateName, string version = null, CancellationToken cancellationToken = default)
        {
            Guard.NotNullOrWhitespace(nameof(certificateName), certificateName);

            var results = new SecretStoreResponse<X509Certificate2>();

            if (_certificates == null)
            {
                using(await _control.LockAsync(cancellationToken).ConfigureAwait(false))
                {
                    if(_certificates == null)
                    {
                        _certificates = _keyVault.GetCertificatesClient(CertificateClientOptions.ServiceVersion.V7_1);
                    }
                }
            }

            var certificateResponse = await _certificates.GetAsync(certificateName, version, cancellationToken).ConfigureAwait(false);

            if(certificateResponse.IsSuccess)
            {
                var secretId = certificateResponse.SecretId;

                var elements = secretId.AbsoluteUri.Split("/", StringSplitOptions.RemoveEmptyEntries);

                if (elements.Length > 2)
                {
                    try
                    {
                        var secretVersion = elements[elements.Length - 1];
                        var name = elements[elements.Length - 2];

                        if (_secrets == null)
                        {
                            using (await _control.LockAsync(cancellationToken).ConfigureAwait(false))
                            {
                                if (_secrets == null)
                                {
                                    _secrets = _keyVault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                                }
                            }
                        }

                        var secretResponse = await _secrets.GetCertificateAsync(name, secretVersion, cancellationToken).ConfigureAwait(false);

                        results.Exception = secretResponse.Exception;
                        results.IsSuccessCode = secretResponse.IsSuccess;
                        results.StatusCode = secretResponse.HttpStatus;
                        results.TimeToExecute = TimeSpan.FromMilliseconds(secretResponse.ElapsedMilliseconds);
                        if (secretResponse.IsSuccess) results.Value = secretResponse.Value;
                    }
                    catch(Exception e)
                    {
                        results.Exception = e;
                        results.IsSuccessCode = false;
                        results.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
                        results.TimeToExecute = TimeSpan.FromMilliseconds(certificateResponse.ElapsedMilliseconds);
                    }
                }
            }
            else
            {
                results.Exception = certificateResponse.Exception;
                results.IsSuccessCode = certificateResponse.IsSuccess;
                results.StatusCode = certificateResponse.HttpStatus;
                results.TimeToExecute = TimeSpan.FromMilliseconds(certificateResponse.ElapsedMilliseconds);
            }

            return results;
        }

        /// <inheritdoc />
        public async Task<SecretStoreResponse<string>> GetSecretAsync(string secretName, string version = null, CancellationToken cancellationToken = default)
        {
            Guard.NotNullOrWhitespace(nameof(secretName), secretName);

            var results = new SecretStoreResponse<string>();

            if (_secrets == null)
            {
                using (await _control.LockAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (_secrets == null)
                    {
                        _secrets = _keyVault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                    }
                }
            }

            var secretResponse = await _secrets.GetAsync(secretName, version, cancellationToken).ConfigureAwait(false);

            results.Exception = secretResponse.Exception;
            results.IsSuccessCode = secretResponse.IsSuccess;
            results.StatusCode = secretResponse.HttpStatus;
            results.TimeToExecute = TimeSpan.FromMilliseconds(secretResponse.ElapsedMilliseconds);           
            if (secretResponse.IsSuccess) results.Value = secretResponse.Value.SecureStringToString();

            return results;
        }

        /// <inheritdoc />
        public async Task<SecretStoreResponse<T>> GetSecretAsync<T>(string secretName, string version = null, CancellationToken cancellationToken = default) where T : class
        {
            var response = new SecretStoreResponse<T>();
            SecretStoreResponse<string> secretStringResponse;

            try
            {
                secretStringResponse = await GetSecretAsync(secretName, version, cancellationToken).ConfigureAwait(false);

                if (secretStringResponse == null)
                {
                    response.Exception = null;
                    response.TimeToExecute = TimeSpan.Zero;
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                }
                else
                {
                    response.Exception = secretStringResponse.Exception;
                    response.TimeToExecute = secretStringResponse.TimeToExecute;
                    
                    if(secretStringResponse.IsSuccessCode)
                    {
                        try
                        {
                            var json = Encoding.UTF8.GetString(Convert.FromBase64String(secretStringResponse.Value));
                            response.Value = JsonConvert.DeserializeObject<T>(json);
                            response.StatusCode = (int)HttpStatusCode.OK;
                            response.IsSuccessCode = true;
                        }
                        catch (Exception e)
                        {
                            response.Exception = new ApplicationException("Error deserializing BASE 64 / UTF-8 encoded JSON", e);
                            response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        }
                    }
                    else
                    {
                        response.StatusCode = secretStringResponse.StatusCode;
                        response.Value = default;
                    }                  
                }
            }
            catch (Exception e)
            {
                response.Exception = e;
                response.TimeToExecute = TimeSpan.Zero;
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
            }

            return response;
        }
        #endregion;
    }
}
