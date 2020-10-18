// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault.tests
{
    #region Using Clauses
    using Azure;
    using Azure.Core;
    using Azure.Security.KeyVault.Certificates;
    using Azure.Security.KeyVault.Certificates.Fakes;
    using Azure.Security.KeyVault.Secrets;
    using Azure.Security.KeyVault.Secrets.Fakes;
    using Microsoft.QualityTools.Testing.Fakes;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using praxicloud.core.containers;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    #endregion

    /// <summary>
    /// Unit tests for the Key Vault certificate interop
    /// </summary>
    [TestClass]
    [ExcludeFromCodeCoverage]
    public class CertificateTests
    {
        #region Test Methods
        /// <summary>
        /// Retrieves a secret from the key vault with version specified using a fake
        /// </summary>
        [TestMethod]
        public void GetCertificateWithVersion()
        {
            const string VaultName = "fakevault1";
            const string SecretName = "secretname1";
            const string SecretVersion = "1aaaaaaa1aa11a1111aaaa11111a1111";
 //           const string SecretValue = "This is the value fake";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";
 //           var getCertificateInvoked = false;
       //     string key = null;
            var path = ContainerEnvironment.IsLinux ? Path.Combine(Environment.CurrentDirectory, "my_contoso_local.pfx") : Path.Combine(Environment.CurrentDirectory, "TestValidationCertificate.pfx");
            var certificate = new X509Certificate2(path, "abc123");
            var certificateString = Convert.ToBase64String(certificate.RawData);

            using (var context = ShimsContext.Create())
            {
                ShimKeyVaultCertificate.AllInstances.CerGet = new FakesDelegates.Func<KeyVaultCertificate, byte[]>((vaultCert) => certificate.RawData);

                var fakeCertificate = new ShimKeyVaultCertificate()
                {
                    NameGet = new FakesDelegates.Func<string>(() => "FakeCert1"),
                    IdGet = new FakesDelegates.Func<Uri>(() => new Uri("cert://FakeCert1")),
                    PropertiesGet = new FakesDelegates.Func<CertificateProperties>(() =>
                    {
                        return new ShimCertificateProperties()
                        {
                            VersionGet = new FakesDelegates.Func<string>(() => SecretVersion),
                            NameGet = new FakesDelegates.Func<string>(() => SecretName),
                            IdGet = new FakesDelegates.Func<Uri>(() => new Uri("cert://FakeCert1"))
                        };
                    })
                };

                ShimCertificateClient.AllInstances.GetCertificateVersionAsyncStringStringCancellationToken = new FakesDelegates.Func<CertificateClient, string, string, CancellationToken, Task<Response<KeyVaultCertificate>>>((client, name, version, cancellationToken) =>
                {
                    var keyVaultFakeCertificateResponse = new FakeResponse<KeyVaultCertificate>(fakeCertificate, 200, "OK", null);

                    return Task.FromResult(keyVaultFakeCertificateResponse as Response<KeyVaultCertificate>);
                });

                var secret = new ShimKeyVaultCertificateWithPolicy();


                var response = new FakeResponse<KeyVaultCertificate>(secret, 200, "OK", null);

                SetupSecretClientConstructorFakes();
                var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
                var client = vault.GetCertificatesClient(CertificateClientOptions.ServiceVersion.V7_1);
                var certificateValue = client.GetAsync(SecretName, SecretVersion).GetAwaiter().GetResult();

                Assert.IsNotNull(certificateValue, "Certificate failed to retrieve");
                Assert.IsTrue(string.Equals(certificateValue.Id.AbsoluteUri, "cert://fakecert1/", StringComparison.Ordinal), "Id not expected");
                Assert.IsTrue(string.Equals(certificateValue.Name, "FakeCert1", StringComparison.Ordinal), "Name not expected");
                Assert.IsTrue(string.Equals(certificateValue.Version, SecretVersion, StringComparison.Ordinal), "Version not expected");
                Assert.IsNull(certificateValue.Policy, "Policy not expected");
            }

        }


        /// <summary>
        /// Tests the persistance of the diagnostics configurations
        /// </summary>
        [TestMethod]
        public void OptionsTests()
        {
            var options = new CertificateClientOptions(CertificateClientOptions.ServiceVersion.V7_1);

            KeyVaultCertificates.ConfigureDiagnostics(options, "app1", true, true, true, true, 2000);
            KeyVaultCertificates.ConfigureRetries(options, RetryMode.Fixed, 3, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(4), TimeSpan.FromMinutes(2));

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
        #region FakeResponse Secret Definition
        /// <summary>
        /// A generic response type that returns certificates
        /// </summary>
        /// <typeparam name="T">A key vault certificate derived type</typeparam>
        [ExcludeFromCodeCoverage]
        public class FakeResponse<T> : Azure.Response<T> where T : KeyVaultCertificate
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
