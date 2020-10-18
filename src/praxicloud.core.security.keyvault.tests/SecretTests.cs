// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault.tests
{
    #region Using Clauses
    using Azure;
    using Azure.Core;
    using Azure.Security.KeyVault.Secrets;
    using Azure.Security.KeyVault.Secrets.Fakes;
    using Microsoft.QualityTools.Testing.Fakes;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    #endregion

    /// <summary>
    /// Unit tests for the Key Vault Secrets interop
    /// </summary>
    [TestClass]
    [ExcludeFromCodeCoverage]
    public class SecretTests
    {
        #region Test Methods
        /// <summary>
        /// Retrieves a secret from the key vault using a fake
        /// </summary>
        [TestMethod]
        public void GetSecret()
        {
            const string VaultName = "fakevault1";
            const string SecretName = "secretname1";
            const string SecretVersion = "1aaaaaaa1aa11a1111aaaa11111a1111";
            const string SecretValue = "This is the value fake";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var getSecretInvoked = false;
            string key = null;

            using (var context = ShimsContext.Create())
            {
                var secret = new KeyVaultSecretFake($"{VaultName}.vault.azure.net", SecretName, SecretVersion, SecretValue);
                var response = new FakeResponse<KeyVaultSecret>(secret, 200, "OK", null);

                SetupSecretClientConstructorFakes();
                ShimSecretClient.AllInstances.GetSecretAsyncStringStringCancellationToken = new FakesDelegates.Func<SecretClient, string, string, CancellationToken, Task<Response<KeyVaultSecret>>>((client, name, version, cancellationToken) =>
                {
                    getSecretInvoked = true;

                    var fakeResponse = response as Response<KeyVaultSecret>;
                    return Task.FromResult(fakeResponse);
                });

                var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
                var client = vault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                var secretValue = client.GetAsync(SecretName).GetAwaiter().GetResult();

                key = secretValue.Value.SecureStringToString();
            }

            Assert.IsTrue(getSecretInvoked, "The fake should be used");
            Assert.IsTrue(string.Equals(key, SecretValue, StringComparison.Ordinal), "Value not expected");
        }

        /// <summary>
        /// Retrieves a secret from the key vault with version specified using a fake
        /// </summary>
        [TestMethod]
        public void GetSecretWithVersion()
        {
            const string VaultName = "fakevault1";
            const string SecretName = "secretname1";
            const string SecretVersion = "1aaaaaaa1aa11a1111aaaa11111a1111";
            const string SecretValue = "This is the value fake";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var getSecretInvoked = false;
            string key = null;

            using (var context = ShimsContext.Create())
            {
                var secret = new KeyVaultSecretFake($"{VaultName}.vault.azure.net", SecretName, SecretVersion, SecretValue);
                var response = new FakeResponse<KeyVaultSecret>(secret, 200, "OK", null);

                SetupSecretClientConstructorFakes();
                ShimSecretClient.AllInstances.GetSecretAsyncStringStringCancellationToken = new FakesDelegates.Func<SecretClient, string, string, CancellationToken, Task<Response<KeyVaultSecret>>>((client, name, version, cancellationToken) =>
                {
                    getSecretInvoked = true;

                    var fakeResponse = response as Response<KeyVaultSecret>;
                    return Task.FromResult(fakeResponse);
                });



                var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
                var client = vault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                var secretValue = client.GetAsync(SecretName, SecretVersion).GetAwaiter().GetResult();

                key = secretValue.Value.SecureStringToString();
            }

            Assert.IsTrue(getSecretInvoked, "The fake should be used");
            Assert.IsTrue(string.Equals(key, SecretValue, StringComparison.Ordinal), "Value not expected");
        }

        /// <summary>
        /// Retrieves a secret from the key vault using a fake with the cancellation token provided
        /// </summary>
        [TestMethod]
        public void GetSecretWithCancellation()
        {
            const string VaultName = "fakevault1";
            const string SecretName = "secretname1";
            const string SecretVersion = "1aaaaaaa1aa11a1111aaaa11111a1111";
            const string SecretValue = "This is the value fake";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var getSecretInvoked = false;
            string key = null;

            using (var context = ShimsContext.Create())
            {
                var secret = new KeyVaultSecretFake($"{VaultName}.vault.azure.net", SecretName, SecretVersion, SecretValue);
                var response = new FakeResponse<KeyVaultSecret>(secret, 200, "OK", null);

                SetupSecretClientConstructorFakes();
                ShimSecretClient.AllInstances.GetSecretAsyncStringStringCancellationToken = new FakesDelegates.Func<SecretClient, string, string, CancellationToken, Task<Response<KeyVaultSecret>>>((client, name, version, cancellationToken) =>
                {
                    getSecretInvoked = true;

                    var fakeResponse = response as Response<KeyVaultSecret>;
                    return Task.FromResult(fakeResponse);
                });

                var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
                var client = vault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                var secretValue = client.GetAsync(SecretName, cancellationToken: CancellationToken.None).GetAwaiter().GetResult();

                key = secretValue.Value.SecureStringToString();
            }

            Assert.IsTrue(getSecretInvoked, "The fake should be used");
            Assert.IsTrue(string.Equals(key, SecretValue, StringComparison.Ordinal), "Value not expected");
        }

        /// <summary>
        /// Retrieves a certificate that has been stored as a secret
        /// </summary>
        [TestMethod]
        public void GetCertificateSecret()
        {
            const string VaultName = "fakevault1";
            const string SecretName = "secretname1";
            const string SecretVersion = "1aaaaaaa1aa11a1111aaaa11111a1111";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var getSecretInvoked = false;
            X509Certificate2 certificateSecret = null;

            using (var context = ShimsContext.Create())
            {
                var path = Path.Combine(Environment.CurrentDirectory, "TestValidationCertificate.pfx");
                var certificate = new X509Certificate2(path, "abc123");
                var certificateString = Convert.ToBase64String(certificate.RawData);
                var secret = new KeyVaultSecretFake($"{VaultName}.vault.azure.net", SecretName, SecretVersion, certificateString);
                var response = new FakeResponse<KeyVaultSecret>(secret, 200, "OK", null);

                SetupSecretClientConstructorFakes();
                ShimSecretClient.AllInstances.GetSecretAsyncStringStringCancellationToken = new FakesDelegates.Func<SecretClient, string, string, CancellationToken, Task<Response<KeyVaultSecret>>>((client, name, version, cancellationToken) =>
                {
                    getSecretInvoked = true;

                    var fakeResponse = response as Response<KeyVaultSecret>;
                    return Task.FromResult(fakeResponse);
                });

                var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
                var client = vault.GetSecretsClient(SecretClientOptions.ServiceVersion.V7_1);
                var secretValue = client.GetCertificateAsync(SecretName, SecretVersion, CancellationToken.None).GetAwaiter().GetResult();

                certificateSecret = secretValue.Value;
            }

            Assert.IsTrue(getSecretInvoked, "The fake should be used");
            Assert.IsNotNull(certificateSecret, "Certificate is null");
            Assert.IsTrue(string.Equals(certificateSecret.Thumbprint, "A449811985D59FC72303860F51CB95F5D3257141", StringComparison.Ordinal), "Certificate thumbprint not expected");
            Assert.IsTrue(string.Equals(certificateSecret.Subject, "CN=Joe Smith, OU=UserAccounts, DC=corp, DC=praxicloud, DC=com", StringComparison.Ordinal), "Certificate subject not expected");
            Assert.IsTrue(string.Equals(certificateSecret.Issuer, "CN=Joe Smith, OU=UserAccounts, DC=corp, DC=praxicloud, DC=com", StringComparison.Ordinal), "Certificate issuer not expected");
            Assert.IsTrue(string.Equals(certificateSecret.SerialNumber, "67EA381F988D5AA94B1569B978062CFB", StringComparison.Ordinal), "Certificate serial number not expected");
            Assert.IsTrue(certificateSecret.NotBefore == DateTime.Parse("2020-09-09 9:42:40 AM"), "Certificate not before not expected");
            Assert.IsTrue(certificateSecret.NotAfter == DateTime.Parse("2070-09-09 9:52:40 AM"), "Certificate not after not expected");
        }

        /// <summary>
        /// Tests the persistance of the diagnostics configurations
        /// </summary>
        [TestMethod]
        public void OptionsTests()
        {
            var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V7_1);

            KeyVaultSecrets.ConfigureDiagnostics(options, "app1", true, true, true, true, 2000);
            KeyVaultSecrets.ConfigureRetries(options, RetryMode.Fixed, 3, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(4), TimeSpan.FromMinutes(2));

            Assert.IsTrue(options.Retry.Delay == TimeSpan.FromMinutes(1), "Delay not expected");
            Assert.IsTrue(options.Retry.MaxDelay == TimeSpan.FromMinutes(4), "Maximum delay not expected");
            Assert.IsTrue(options.Retry.NetworkTimeout == TimeSpan.FromMinutes(2), "Network timeout not expected");
            Assert.IsTrue(options.Retry.MaxRetries == 3, "Maximum retries not expected");
            Assert.IsTrue(options.Retry.Mode == RetryMode.Fixed, "Retry mode not expected");

            Assert.IsTrue(options.Diagnostics.IsLoggingContentEnabled, "Is logging content enabled not expected");
            Assert.IsTrue(options.Diagnostics.IsLoggingEnabled, "Is logging enabled not expected");
            Assert.IsTrue(options.Diagnostics.IsTelemetryEnabled, "Is telemetry enabled not expected");
            Assert.IsTrue(options.Diagnostics.IsDistributedTracingEnabled, "Is distributed tracing enabled not expected");
            Assert.IsTrue(options.Diagnostics.LoggedContentSizeLimit == 2000, "Logging content size not expected"); 
            Assert.IsTrue(string.Equals(options.Diagnostics.ApplicationId, "app1", StringComparison.Ordinal), "Application id not expected");
        }
        #endregion
        #region Support Methods
        /// <summary>
        /// Initializes the secret client constructors to use fakes
        /// </summary>
        public void SetupSecretClientConstructorFakes()
        {
            ShimSecretClient.Constructor = new FakesDelegates.Action<SecretClient>((client) =>
            {

            });

            ShimSecretClient.ConstructorUriTokenCredential = new FakesDelegates.Action<SecretClient, Uri, TokenCredential>((client, uri, credential) =>
            {

            });

            ShimSecretClient.ConstructorUriTokenCredentialSecretClientOptions = new FakesDelegates.Action<SecretClient, Uri, TokenCredential, SecretClientOptions>((client, uri, credential, options) =>
            {

            });
        }
        #endregion
        #region KeyVaultSecretFake Definition
        /// <summary>
        /// A key vault secret fake for unit tests
        /// </summary>
        [ExcludeFromCodeCoverage]
        public class KeyVaultSecretFake : KeyVaultSecret
        {
            #region Constructors
            /// <summary>
            /// Initializes a new instance of the type
            /// </summary>
            /// <param name="vaultName">The name of the key vault</param>
            /// <param name="name">The name of the secret</param>
            /// <param name="version">The version of the secret</param>
            /// <param name="value">The value of the secret</param>
            public KeyVaultSecretFake(string vaultName, string name, string version, string value) : base(name, value)
            {
                Id = new Uri($"https://{ vaultName }/secrets/{ name }/{ version }");
                Value = value;
            }
            #endregion
            #region Properties
            /// <summary>
            /// Hides the base Id value
            /// </summary>
            public new Uri Id { get; }

            /// <summary>
            /// Hids the base Value 
            /// </summary>
            public new string Value { get; }
            #endregion
        }
        #endregion
        #region FakeResponse Secret Definition
        /// <summary>
        /// A generic response type that returns secrets
        /// </summary>
        /// <typeparam name="T">A secret derived type</typeparam>
        [ExcludeFromCodeCoverage]
        public class FakeResponse<T> : Azure.Response<T> where T : KeyVaultSecret
        {
            #region Variables
            /// <summary>
            /// The response to be provided back from the fake when requested
            /// </summary>
            private readonly Response _response;
            #endregion
            #region Constructors
            public FakeResponse(T value, int status, string reasonPhrase, Dictionary<string, HttpHeader> headers = null)
            {
                _response = new FakeResponse(status, reasonPhrase, headers);
                Value = value;
            }
            #endregion
            #region Properties
            /// <inheritdoc />
            public override T Value { get; }
            #endregion
            #region Methods
            /// <inheritdoc />
            public override Response GetRawResponse()
            {
                return _response;
            }
            #endregion
        }
        #endregion
    }
}
