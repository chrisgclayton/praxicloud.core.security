// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault
{
    #region Using Clauses
    using System;
    #endregion

    /// <summary>
    /// A response from Key Vault operation
    /// </summary>
    public class KeyVaultResponse
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="secret">The key vault secret</param>
        /// <param name="httpStatus">The http status code returned</param>
        /// <param name="elapsedMilliseconds">The number of milliseconds that elapsed executing the query</param>
        internal KeyVaultResponse(int httpStatus, long elapsedMilliseconds)
        {
            ElapsedMilliseconds = elapsedMilliseconds;
            Exception = null;
            HttpStatus = httpStatus;
        }

        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="exception">An exception that represents the failure</param>
        internal KeyVaultResponse(Exception exception)
        {
            Guard.NotNull(nameof(exception), exception);

            ElapsedMilliseconds = 0;
            Exception = exception;
            HttpStatus = 0;
        }
        #endregion
        #region Properties
        /// <summary>
        /// The Http status code that was returned or 0 if an exception was raised
        /// </summary>
        public int HttpStatus { get; }

        /// <summary>
        /// True if the Http request was successful
        /// </summary>
        public bool IsSuccess => (HttpStatus >= 200 && HttpStatus <= 299);

        /// <summary>
        /// The exception that was returned
        /// </summary>
        public Exception Exception { get; }

        /// <summary>
        /// The number of milliseconds that elapsed executing the query or 0 if an exception was raised
        /// </summary>
        public long ElapsedMilliseconds { get; }
        #endregion
        #region Operators
        /// <summary>
        /// Implicit casting of the response to a boolean indicating the success of the response
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator bool(KeyVaultResponse response)
        {
            return response.IsSuccess;
        }

        /// <summary>
        /// Implicit casting of the response to a integer indicating the Http status code
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator int(KeyVaultResponse response)
        {
            return response.HttpStatus;
        }

        /// <summary>
        /// Implicit casting of the response to an Exception indicating the exception that was raised
        /// </summary>
        /// <param name="response">The response to cast</param>
        public static implicit operator Exception(KeyVaultResponse response)
        {
            return response.Exception;
        }
        #endregion
    }
}
