// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    using System.Collections.Generic;
    using Azure.Security.KeyVault.Keys;
    #endregion

    /// <summary>
    /// A response from Key Vault for secret retrieval
    /// </summary>
    public class KeyVaultKeyResponse : KeyVaultResponse
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="key">The key vault key</param>
        /// <param name="httpStatus">The http status code returned</param>
        /// <param name="elapsedMilliseconds">The number of milliseconds that elapsed executing the query</param>
        internal KeyVaultKeyResponse(KeyVaultKey key, int httpStatus, long elapsedMilliseconds) : base(httpStatus, elapsedMilliseconds)
        {
            Id = key.Id;
            Name = key.Name;

            Value = key.Key;
            Operations = key.KeyOperations;
            KeyType = key.KeyType;
            Properties = key.Properties;
        }

        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="name">The name of the secret being retrieved</param>
        /// <param name="version">The version of the secret being retrieved</param>
        /// <param name="exception">An exception that represents the failure</param>
        internal KeyVaultKeyResponse(string name, string version, Exception exception) : base(exception)
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
        /// The version of the secret being requested
        /// </summary>
        public string Version { get; }

        /// <summary>
        /// The key that was retrieved
        /// </summary>
        public JsonWebKey Value { get; }

        /// <summary>
        /// The operations that can be performed on the key
        /// </summary>
        public IReadOnlyCollection<KeyOperation> Operations;

        /// <summary>
        /// The type of the key
        /// </summary>
        public KeyType KeyType { get; }

        /// <summary>
        /// The properties of the key
        /// </summary>
        public KeyProperties Properties { get; }
        #endregion
        #region Operators
        /// <summary>
        /// Implicit casting of the response to a JsonWebKey being the value that was retrieved
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator JsonWebKey(KeyVaultKeyResponse response)
        {
            return response.Value;
        }
        #endregion
    }
}
