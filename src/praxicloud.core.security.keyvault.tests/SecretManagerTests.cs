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
    /// Unit tests for the Key Vault secret manager
    /// </summary>
    [TestClass]
    [ExcludeFromCodeCoverage]
    public class SecretManagerTests
    {
        /// <summary>
        /// Retrieves a secret from Key Vault through the secret manager interfaces
        /// </summary>
        [TestMethod]
        public void GetSecret()
        {
            const string TenantId = @"11a111aa-11a1-11aa-11aa-1a1aa111aa11";
            const string ClientId = @"11a111aa-11a1-11aa-11aa-1a1aa111aa11";
            const string ClientSecret = @"someclientsecret";
            const string SecretName = @"fakesecret";
            const string SecretVersion = @"11a111aa11a111aa11aa1a1aa111aa11";

            var manager = new KeyVaultSecretManager("cgcvault1", AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
            var response = manager.GetSecretAsync(SecretName, SecretVersion, CancellationToken.None).GetAwaiter().GetResult();

            Assert.IsNotNull(response, "Response is null");
            Assert.IsTrue(response.IsSuccessCode, "Success code unexpected");
            Assert.IsTrue(response.StatusCode == 200, "Status code unexpected");
        }

        /// <summary>
        /// Retrieves a certificate from Key Vault through the secret manager interfaces
        /// </summary>
        [TestMethod]
        public void GetCertificate()
        {
            const string TenantId = @"11a111aa-11a1-11aa-11aa-1a1aa111aa11";
            const string ClientId = @"11a111aa-11a1-11aa-11aa-1a1aa111aa11";
            const string ClientSecret = @"someclientsecret";
            const string CertificateName = @"democert123";
            const string CertificateVersion = @"11a111aa11a111aa11aa1a1aa111aa11";

            var manager = new KeyVaultSecretManager("cgcvault1", AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));
            var response = manager.GetCertificateAsync(CertificateName, CertificateVersion, CancellationToken.None).GetAwaiter().GetResult();

            Assert.IsNotNull(response, "Response is null");
            Assert.IsTrue(response.IsSuccessCode, "Success code unexpected");
            Assert.IsTrue(response.StatusCode == 200, "Status code unexpected");
        }

    }
}
