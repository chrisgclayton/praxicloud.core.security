// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using Azure.Security.KeyVault.Secrets;
    using System;
    using System.Security.Cryptography.X509Certificates;
    #endregion

    /// <summary>
    /// A response from Key Vault for secret retrieval
    /// </summary>
    public class KeyVaultSecretCertificateResponse : KeyVaultResponse
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="secret">The key vault secret</param>
        /// <param name="httpStatus">The http status code returned</param>
        /// <param name="elapsedMilliseconds">The number of milliseconds that elapsed executing the query</param>
        internal KeyVaultSecretCertificateResponse(KeyVaultSecret secret, int httpStatus, long elapsedMilliseconds) : base(httpStatus, elapsedMilliseconds)
        {
            Id = secret.Id;
            Name = secret.Name;
            ContentType = secret.Properties.ContentType;
            Enabled = secret.Properties.Enabled;
            ExpiresOn = secret.Properties.ExpiresOn;
            Version = secret.Properties.Version;

            if(IsSuccess)
            {
                Value = new X509Certificate2(Convert.FromBase64String(secret.Value));
            }
            else
            {
                Value = null;
            }
        }

        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="name">The name of the secret being retrieved</param>
        /// <param name="version">The version of the secret being retrieved</param>
        /// <param name="exception">An exception that represents the failure</param>
        internal KeyVaultSecretCertificateResponse(string name, string version, Exception exception) : base(exception)
        {
            Name = name;
            Version = version;
        }
        #endregion
        #region Properties
        /// <summary>
        /// The name of the secret being retrieved
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The id of the secret that was retrieved
        /// </summary>
        public Uri Id { get; }

        /// <summary>
        /// The value of the secret
        /// </summary>
        public X509Certificate2 Value { get; }

        /// <summary>
        /// The content type of the secret retrieved
        /// </summary>
        public string ContentType { get; }

        /// <summary>
        /// True if enabled and set
        /// </summary>
        public bool? Enabled { get; }

        /// <summary>
        /// The expiration date if set
        /// </summary>
        public DateTimeOffset? ExpiresOn { get; }

        /// <summary>
        /// The version of the secret being requested
        /// </summary>
        public string Version { get; }
        #endregion
        #region Operators
        /// <summary>
        /// Implicit casting of the response to a certificate being the value that was retrieved
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator X509Certificate2(KeyVaultSecretCertificateResponse response)
        {
            return response.Value;
        }
        #endregion
    }
}
