// Copyright (c) Chris Clayton. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace praxicloud.core.security.keyvault.tests
{
    #region Using Clauses
    using Azure.Core;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    #endregion

    /// <summary>
    /// A simple fake for Azure Response to use when retrieving information from the vault
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class FakeResponse : Azure.Response
    {
        #region Variables
        /// <summary>
        /// A dictionary to represent the headers
        /// </summary>
        private readonly ConcurrentDictionary<string, HttpHeader> _headers;
        #endregion
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the type
        /// </summary>
        /// <param name="status">The HTTP Status Code</param>
        /// <param name="reasonPhrase">A text based response representing the HTTP response</param>
        /// <param name="headers">A list of headers if present or null if none are in use</param>
        /// <param name="clientRequestId">The client request ID if in use in the test</param>
        /// <param name="contentStream">The content of the HTTP or null if no content returned or in use in the unit test</param>
        public FakeResponse(int status, string reasonPhrase, Dictionary<string, HttpHeader> headers = null, string clientRequestId = null, MemoryStream contentStream = null)
        {
            ClientRequestId = clientRequestId;
            Status = status;
            ReasonPhrase = reasonPhrase;
            _headers = (headers?.Count ?? 0) == 0 ? new ConcurrentDictionary<string, HttpHeader>() : new ConcurrentDictionary<string, HttpHeader>(headers);
            ContentStream = contentStream;
        }
        #endregion
        #region Properties
        /// <inheritdoc />
        public override int Status { get; }

        /// <inheritdoc />
        public override string ReasonPhrase { get; }

        /// <inheritdoc />
        public override Stream ContentStream { get; set; }

        /// <inheritdoc />
        public override string ClientRequestId { get; set; }
        #endregion
        #region Methods
        /// <inheritdoc />
        public override void Dispose()
        {
        }

        /// <inheritdoc />
        protected override bool ContainsHeader(string name)
        {
            return _headers.ContainsKey(name);
        }

        /// <inheritdoc />
        protected override IEnumerable<HttpHeader> EnumerateHeaders()
        {
            return _headers.Values.AsEnumerable();
        }

        /// <inheritdoc />
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string value)
        {
            var getStatus = _headers.TryGetValue(name, out var header);

            value = header.Value;

            return getStatus;
        }

        /// <inheritdoc />
        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string> values)
        {
            var getStatus = _headers.TryGetValue(name, out var header);

            var headerValues = new List<string>();
            headerValues.Add(header.Value);

            values = headerValues.AsEnumerable();

            return getStatus;
        }
        #endregion
    }
}
