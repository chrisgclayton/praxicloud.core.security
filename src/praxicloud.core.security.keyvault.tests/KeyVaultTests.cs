// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault.tests
{
    #region Using Clauses
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Diagnostics.CodeAnalysis;
    #endregion

    /// <summary>
    /// Unit tests for the Key Vault base object
    /// </summary>
    [TestClass]
    [ExcludeFromCodeCoverage]
    public class KeyVaultTests
    {
        /// <summary>
        /// Gets and sets the common properties
        /// </summary>
        [TestMethod]
        public void GetSet()
        {
            const string VaultName = "fakevault1";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));

            Assert.IsTrue(string.Equals(vault.Name, VaultName, StringComparison.Ordinal), "Vault name is not expected");
            Assert.IsTrue(string.Equals(vault.FullyQualifiedName, $"{ VaultName }.vault.azure.net", StringComparison.Ordinal), "Fully qualified name is not expected");
            Assert.IsTrue(string.Equals(vault.Uri.AbsoluteUri, $"https://{ VaultName }.vault.azure.net/", StringComparison.Ordinal), "Uri not expected");
            Assert.IsFalse(vault.EnableDiagnostics, "Enable diagnostics not expected");
            Assert.IsTrue(vault.MaximumDelay == TimeSpan.FromSeconds(15), "Maximum delay not expected");
            Assert.IsTrue(vault.NetworkTimeout == TimeSpan.FromSeconds(10), "Network timeout not expected");
            Assert.IsTrue(vault.Delay == TimeSpan.FromSeconds(2), "Delay not expected");
            Assert.IsTrue(vault.MaximumRetries == 3, "Maximum retries not expected");
            Assert.IsNull(vault.DiagnosticsApplicationId, "Diagnostics application id not expected");
        }


        /// <summary>
        /// Gets and sets the common properties
        /// </summary>
        [TestMethod]
        public void GetSetWithDiagnostics()
        {
            const string VaultName = "fakevault1";
            const string TenantId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientId = "11111111-1111-1111-aa1a-a1a11a111111";
            const string ClientSecret = "a.u8w3FFgwy9v_-5R_5gsT~qf96T~a7e6y";

            var vault = new KeyVault(VaultName, AzureOauthTokenAuthentication.GetOauthTokenCredentialFromClientSecret(TenantId, ClientId, ClientSecret), 3, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(10));

            vault.EnableDiagnostics = true;
            vault.DiagnosticsApplicationId = "demo";

            Assert.IsTrue(string.Equals(vault.Name, VaultName, StringComparison.Ordinal), "Vault name is not expected");
            Assert.IsTrue(string.Equals(vault.FullyQualifiedName, $"{ VaultName }.vault.azure.net", StringComparison.Ordinal), "Fully qualified name is not expected");
            Assert.IsTrue(string.Equals(vault.Uri.AbsoluteUri, $"https://{ VaultName }.vault.azure.net/", StringComparison.Ordinal), "Uri not expected");
            Assert.IsTrue(vault.EnableDiagnostics, "Enable diagnostics not expected");
            Assert.IsTrue(vault.MaximumDelay == TimeSpan.FromSeconds(15), "Maximum delay not expected");
            Assert.IsTrue(vault.NetworkTimeout == TimeSpan.FromSeconds(10), "Network timeout not expected");
            Assert.IsTrue(vault.Delay == TimeSpan.FromSeconds(2), "Delay not expected");
            Assert.IsTrue(vault.MaximumRetries == 3, "Maximum retries not expected");
            Assert.IsTrue(string.Equals(vault.DiagnosticsApplicationId, "demo", StringComparison.Ordinal), "Diagnostics application id not expected");
        }
    }
}
