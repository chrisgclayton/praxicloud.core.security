// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    using Azure.Security.KeyVault.Certificates;
    #endregion

    /// <summary>
    /// A response from Key Vault for certificate retrieval
    /// </summary>
    public class KeyVaultCertificateResponse : KeyVaultResponse
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="certificate">The key vault certificate</param>
        /// <param name="httpStatus">The http status code returned</param>
        /// <param name="elapsedMilliseconds">The number of milliseconds that elapsed executing the query</param>
        internal KeyVaultCertificateResponse(KeyVaultCertificateWithPolicy certificate, int httpStatus, long elapsedMilliseconds) : this((KeyVaultCertificate)certificate, httpStatus, elapsedMilliseconds)
        {
            Policy = certificate.Policy;
        }

        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="certificate">The key vault certificate</param>
        /// <param name="httpStatus">The http status code returned</param>
        /// <param name="elapsedMilliseconds">The number of milliseconds that elapsed executing the query</param>
        internal KeyVaultCertificateResponse(KeyVaultCertificate certificate, int httpStatus, long elapsedMilliseconds) : base(httpStatus, elapsedMilliseconds)
        {
            Id = certificate.Id;
            Name = certificate.Name;
            Version = certificate.Properties.Version;

            Properties = certificate.Properties;
            Value = certificate.Cer;
            SecretId = certificate.SecretId;
            KeyId = certificate.KeyId;
            Policy = null;
        }

        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="name">The name of the secret being retrieved</param>
        /// <param name="version">The version of the secret being retrieved</param>
        /// <param name="exception">An exception that represents the failure</param>
        internal KeyVaultCertificateResponse(string name, string version, Exception exception) : base(exception)
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
        /// The contents of the certificate
        /// </summary>
        public byte[] Value { get; }

        /// <summary>
        /// Properties of the certificate retreived
        /// </summary>
        public CertificateProperties Properties { get; }

        /// <summary>
        /// The id of the secret that back the certificate with the key etc.
        /// </summary>
        public Uri SecretId { get; }

        /// <summary>
        /// The id of the key that backs the certificate
        /// </summary>
        public Uri KeyId { get; }

        /// <summary>
        /// The certificate policy
        /// </summary>
        public CertificatePolicy Policy { get; }

        /// <summary>
        /// The version of the secret being requested
        /// </summary>
        public string Version { get; }
        #endregion
        #region Operators
        /// <summary>
        /// Implicit casting of the response to the certificate being the value that was retrieved
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator byte[](KeyVaultCertificateResponse response)
        {
            return response.Value;
        }

        /// <summary>
        /// Implicit casting of the response to a certificate policy
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator CertificatePolicy(KeyVaultCertificateResponse response)
        {
            return response.Policy;
        }

        /// <summary>
        /// Implicit casting of the response to certificate properties
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator CertificateProperties(KeyVaultCertificateResponse response)
        {
            return response.Properties;
        }
        #endregion
    }
}
