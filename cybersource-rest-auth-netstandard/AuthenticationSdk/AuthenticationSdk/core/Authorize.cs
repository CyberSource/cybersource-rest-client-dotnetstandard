using System;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.authentication.oauth;
using AuthenticationSdk.util;
using NLog;

namespace AuthenticationSdk.core
{
    /*==============================================================================
    * Provides Methods to Generate HTTP Authentication Headers of CYBS REST API's
    *===============================================================================*/
    public class Authorize
    {
        private static Logger _logger;
        private readonly MerchantConfig _merchantConfig;
        LogUtility logUtility;

        public Authorize(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            Enumerations.ValidateRequestType(_merchantConfig.RequestType);
            Enumerations.SetRequestType(_merchantConfig);
            logUtility = new LogUtility();

            if (_logger == null)
            {
                _logger = LogManager.GetCurrentClassLogger();
            }
        }

        private void LogMerchantDetails()
        {
            try
            {
                // Using Request Target provided in the sample code/merchantconfig
                _logger.Debug($"Request Target: '{_merchantConfig.RequestTarget}'");

                // logging Authentication type
                _logger.Debug($"Authentication Type: {_merchantConfig.AuthenticationType}");

                // logging Request Type
                _logger.Debug($"Request Type: {_merchantConfig.RequestType}");

                // Logging all the Properties of MerchantConfig and their respective Values
                _merchantConfig.LogMerchantConfigurationProperties();
            }
            catch (Exception e)
            {
                _logger.Error($"Failed to log merchant details: {e.Message}", e);
                throw new AuthenticationException("LOG_ERROR", $"Failed to log merchant configuration details: {e.Message}", e);
            }
        }

        #region Properties
        private readonly IMerchantRequestSettings _merchantRequestSettings;
        private readonly IMerchantCredentialSettings _merchantCredentialSettings;
        private readonly IMerchantMLESettings _merchantMLESettings;
        #endregion Properties

        #region Constructor
        public Authorize(IMerchantCredentialSettings merchantCredentialSettings, IMerchantRequestSettings merchantRequestSettings, IMerchantMLESettings merchantMLESettings)
        {
            _merchantRequestSettings = merchantRequestSettings;
            _merchantCredentialSettings = merchantCredentialSettings;
            _merchantMLESettings = merchantMLESettings;

            logUtility = new LogUtility();

            if (_logger == null)
            {
                _logger = LogManager.GetCurrentClassLogger();
            }
        }
        #endregion Constructor

        #region Methods
        public HttpToken GetSignature()
        {
            try
            {
                var signatureObject = (HttpToken)new HttpTokenGenerator(_merchantCredentialSettings, _merchantRequestSettings).GetToken();

                _logger.Debug($"v-c-merchant-id: {signatureObject.MerchantId}");
                _logger.Debug($"Date: {signatureObject.GmtDateTime}");
                _logger.Debug($"Host: {signatureObject.HostName}");

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/hal+json");
                    logUtility.LogDebugMessage(_logger, $"digest: {signatureObject.Digest}");
                }

                logUtility.LogDebugMessage(_logger, $"Signature : {signatureObject.SignatureParam}");

                return signatureObject;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
            }
        }

        public JwtToken GetToken(bool isResponseMLEForApi = false)
        {
            try
            {
                var tokenObject = (JwtToken) new JwtTokenGenerator(_merchantCredentialSettings, _merchantRequestSettings, _merchantMLESettings, isResponseMLEForApi).GetToken();

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/hal+json");
                }

                //logUtility.LogDebugMessage(_logger, $"Authorization : Bearer {tokenObject.BearerToken}");

                return tokenObject;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
            }
        }

        public OAuthToken GetOAuthToken()
        {
            try
            {
                var tokenObject = (OAuthToken)new OAuthTokenGenerator(_merchantCredentialSettings).GetToken();

                if (_merchantRequestSettings.RequestType.Equals("GET", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("DELETE", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/json");
                }
                else if (_merchantRequestSettings.RequestType.Equals("POST", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PUT", StringComparison.InvariantCultureIgnoreCase) || _merchantRequestSettings.RequestType.Equals("PATCH", StringComparison.InvariantCultureIgnoreCase))
                {
                    _logger.Debug("Content-Type: application/hal+json");
                }

                return tokenObject;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
            }
        }
        #endregion Methods
    }
}