using System;
using AuthenticationSdk.authentication.http;
using AuthenticationSdk.authentication.jwt;
using AuthenticationSdk.util;
using NLog;

namespace AuthenticationSdk.core
{
    /*==============================================================================
    * Provides Methods to Generate HTTP Authentication Headers of CYBS REST API's
    *===============================================================================*/
    public class Authorize
    {
        private readonly Logger _logger = LogManager.GetCurrentClassLogger();
        private readonly MerchantConfig _merchantConfig;

        public Authorize(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            Enumerations.ValidateRequestType(_merchantConfig.RequestType);
            Enumerations.SetRequestType(_merchantConfig);
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

                    var signatureObj = (HttpToken)new HttpTokenGenerator(_merchantConfig).GetToken();

                    if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
                    {
                        _logger.Trace("{0} {1}", "Content-Type:", "application/json");
                    }

                    if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Trace("{0} {1}", "Content-Type:", "application/hal+json");
                    }

                    _logger.Trace("{0} {1}", "v-c-merchant-id:", signatureObj.MerchantId);
                    _logger.Trace("{0} {1}", "Date:", signatureObj.GmtDateTime);
                    _logger.Trace("{0} {1}", "Host:", signatureObj.HostName);

                    if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Trace("{0} {1}", "digest:", signatureObj.Digest);
                    }

                    _logger.Trace("{0} {1}", "signature:", signatureObj.SignatureParam);

                    return signatureObj;
                }

                return null;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
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

                    var tokenObj = (JwtToken)new JwtTokenGenerator(_merchantConfig).GetToken();

                    if (_merchantConfig.IsGetRequest || _merchantConfig.IsDeleteRequest)
                    {
                        _logger.Trace("{0} {1}", "Content-Type:", "application/json");
                    }
                    else if (_merchantConfig.IsPostRequest || _merchantConfig.IsPutRequest || _merchantConfig.IsPatchRequest)
                    {
                        _logger.Trace("{0} {1}", "Content-Type:", "application/hal+json");
                    }

                    _logger.Trace("{0} {1}", "Authorization:", tokenObj.BearerToken);

                    return tokenObj;
                }

                return null;
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
                return null;
            }
        }

        private void LogMerchantDetails()
        {
            try
            {
                // Using Request Target provided in the sample code/merchantconfig
                _logger.Trace("Using Request Target:'{0}'", _merchantConfig.RequestTarget);

                // logging Authentication type
                _logger.Trace("Authentication Type -> {0}", _merchantConfig.AuthenticationType);

                // logging Request Type
                _logger.Trace("Request Type -> {0}", _merchantConfig.RequestType);

                // Logging all the Properties of MerchantConfig and their respective Values
                _logger.Trace("MERCHCFG > {0}", MerchantConfig.LogAllproperties(_merchantConfig));
            }
            catch (Exception e)
            {
                ExceptionUtility.Exception(e.Message, e.StackTrace);
            }
        }
    }
}
