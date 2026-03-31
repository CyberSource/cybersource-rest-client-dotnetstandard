using System;

namespace AuthenticationSdk.core
{
    /// <summary>
    /// Base exception class for authentication-related errors in the CyberSource Authentication SDK.
    /// Provides enhanced error handling with inner exception support for better debugging.
    /// </summary>
    public class AuthenticationException : Exception
    {
        /// <summary>
        /// Gets or sets the error code associated with this authentication exception.
        /// </summary>
        public string ErrorCode { get; set; }

        /// <summary>
        /// Gets or sets additional error context information.
        /// </summary>
        public object ErrorContext { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class.
        /// </summary>
        public AuthenticationException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public AuthenticationException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public AuthenticationException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class with error code, message, and inner exception.
        /// </summary>
        /// <param name="errorCode">The error code associated with this exception.</param>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public AuthenticationException(string errorCode, string message, Exception innerException = null) : base(message, innerException)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class with error code, message, context, and inner exception.
        /// </summary>
        /// <param name="errorCode">The error code associated with this exception.</param>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="errorContext">Additional error context information.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public AuthenticationException(string errorCode, string message, object errorContext, Exception innerException = null) : base(message, innerException)
        {
            ErrorCode = errorCode;
            ErrorContext = errorContext;
        }
    }


    /// <summary>
    /// Exception thrown when certificate or key-related errors occur.
    /// </summary>
    public class CertificateException : AuthenticationException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateException"/> class.
        /// </summary>
        public CertificateException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public CertificateException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public CertificateException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Exception thrown when token generation errors occur.
    /// </summary>
    public class TokenGenerationException : AuthenticationException
    {
        /// <summary>
        /// Gets or sets the token type that failed to generate.
        /// </summary>
        public string TokenType { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenGenerationException"/> class.
        /// </summary>
        public TokenGenerationException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenGenerationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public TokenGenerationException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenGenerationException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public TokenGenerationException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenGenerationException"/> class with token type, message, and inner exception.
        /// </summary>
        /// <param name="tokenType">The type of token that failed to generate.</param>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public TokenGenerationException(string tokenType, string message, Exception innerException = null) : base(message, innerException)
        {
            TokenType = tokenType;
        }
    }

    /// <summary>
    /// Exception thrown when MLE (Message Level Encryption) errors occur.
    /// </summary>
    public class MLEException : AuthenticationException
    {
        /// <summary>
        /// Gets or sets the MLE operation that failed.
        /// </summary>
        public string Operation { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MLEException"/> class.
        /// </summary>
        public MLEException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MLEException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public MLEException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MLEException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public MLEException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MLEException"/> class with operation, message, and inner exception.
        /// </summary>
        /// <param name="operation">The MLE operation that failed.</param>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public MLEException(string operation, string message, Exception innerException = null) : base(message, innerException)
        {
            Operation = operation;
        }
    }

    /// <summary>
    /// Exception thrown when there are configuration-related errors in the Authentication SDK.
    /// </summary>
    public class ConfigurationException : AuthenticationException
    {
        /// <summary>
        /// Gets or sets the configuration key that caused the error.
        /// </summary>
        public string ConfigurationKey { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationException"/> class.
        /// </summary>
        public ConfigurationException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public ConfigurationException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public ConfigurationException(string message, Exception innerException) : base(message, innerException) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationException"/> class with configuration key, message, and inner exception.
        /// </summary>
        /// <param name="configurationKey">The configuration key that caused the error.</param>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public ConfigurationException(string configurationKey, string message, Exception innerException = null) : base("CONFIG_ERROR", message, innerException)
        {
            ConfigurationKey = configurationKey;
        }
    }
}