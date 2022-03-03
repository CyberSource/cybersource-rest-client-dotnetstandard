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

        public Authorize(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            Enumerations.ValidateRequestType(_merchantConfig.RequestType);
            Enumerations.SetRequestType(_merchantConfig);

            if (_logger == null)
            {
                _logger = LogManager.GetCurrentClassLogger();
            }
        }

        /**
         * @return an HttpToken object (HTTP Signature Headers),
         * based on the Merchant Configuration passed to the Constructor of Authorize Class
         */
        public HttpToken GetSignature()
        {
            try
            {
                if (_merchantConfig != null)
                {
                    LogMerchantDetails();

                    Enumerations.ValidateRequestType(_merchantConfig.RequestType);

                    if (string.IsNullOrEmpty(_merchantConfig.MerchantId) || string.IsNullOrEmpty(_merchantConfig.MerchantKeyId) || string.IsNullOrEmpty(_merchantConfig.MerchantSecretKey))
                    {
                        throw new Exception("Missing or Empty Credentials : MerchantID or MerchantKeyID or MerchantSecretKey");
                    }

                    var signatureObj = (HttpToken)new HttpTokenGenerator(_merchantConfig).GetToken();

                    if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
                    {
                        _logger.Debug("Content-Type: application/json");
                    }
                    else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Debug("Content-Type: application/hal+json");
                    }

                    _logger.Debug($"v-c-merchant-id: {signatureObj.MerchantId}");
                    _logger.Debug($"Date: {signatureObj.GmtDateTime}");
                    _logger.Debug($"Host: {signatureObj.HostName}");

                    if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Debug($"digest: {signatureObj.Digest}");
                    }

                    _logger.Debug($"signature: {signatureObj.SignatureParam}");

                    return signatureObj;
                }

                return null;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
            }
        }

        /**
         * @return a JwtToken object (JWT Bearer Token), 
         * based on the Merchant Configuration passed to the Constructor of Authorize Class
         */
        public JwtToken GetToken()
        {
            try
            {
                if (_merchantConfig != null)
                {
                    LogMerchantDetails();

                    Enumerations.ValidateRequestType(_merchantConfig.RequestType);

                    if (string.IsNullOrEmpty(_merchantConfig.MerchantId) || string.IsNullOrEmpty(_merchantConfig.KeyAlias) || string.IsNullOrEmpty(_merchantConfig.KeyPass))
                    {
                        throw new Exception("Missing or Empty Credentials : MerchantID or KeyAlias or KeyPassphrase");
                    }

                    var tokenObj = (JwtToken)new JwtTokenGenerator(_merchantConfig).GetToken();

                    if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
                    {
                        _logger.Debug("Content-Type: application/json");
                    }
                    else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Debug("Content-Type: application/hal+json");
                    }

                    _logger.Debug($"Authorization: {tokenObj.BearerToken}");

                    return tokenObj;
                }

                return null;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
            }
        }

        /**
         * @return a OAuthToken object (OAuth Bearer Token), 
         * based on the Merchant Configuration passed to the Constructor of Authorize Class
         */
        public OAuthToken GetOAuthToken()
        {
            try
            {
                if (_merchantConfig != null)
                {
                    LogMerchantDetails();

                    Enumerations.ValidateRequestType(_merchantConfig.RequestType);

                    if (string.IsNullOrEmpty(_merchantConfig.AccessToken) || string.IsNullOrEmpty(_merchantConfig.RefreshToken))
                    {
                        throw new Exception("Missing or Empty Credentials : AccessToken or RefreshToken");
                    }

                    var tokenObj = (OAuthToken)new OAuthTokenGenerator(_merchantConfig).GetToken();

                    if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
                    {
                        _logger.Debug("Content-Type: application/json");
                    }
                    else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Debug("Content-Type: application/hal+json");
                    }

                    _logger.Debug($"Authorization: {tokenObj.AccessToken}");

                    return tokenObj;
                }

                return null;
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                throw e;
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
                _logger.Error(e.Message);
                throw e;
            }
        }
    }
}
