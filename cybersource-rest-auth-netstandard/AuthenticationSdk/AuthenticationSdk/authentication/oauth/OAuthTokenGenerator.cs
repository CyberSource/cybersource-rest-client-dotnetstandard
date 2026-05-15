using System;
using System.Collections.Generic;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.oauth
{
    public class OAuthTokenGenerator : ITokenGenerator
    {
        private readonly OAuthToken _oauthtoken;

        public Token GetToken()
        {
            try
            {
                if (_oauthtoken == null)
                {
                    throw new TokenGenerationException("OAuth", "OAuth token object is null");
                }

                if (string.IsNullOrEmpty(_oauthtoken.AccessToken))
                {
                    throw new ConfigurationException("OAuth AccessToken is missing or empty");
                }

                return _oauthtoken;
            }
            catch (TokenGenerationException)
            {
                // Re-throw token generation exceptions as-is
                throw;
            }
            catch (ConfigurationException)
            {
                // Re-throw configuration exceptions as-is
                throw;
            }
            catch (Exception e)
            {
                throw new TokenGenerationException("OAuth", $"Failed to generate OAuth token: {e.Message}", e);
            }
        }

        #region NEW PROPERTIES
        private readonly IMerchantCredentialSettings _merchantCredentialSettings;
        #endregion

        #region NEW CONSTRUCTOR
        public OAuthTokenGenerator(IMerchantCredentialSettings merchantCredentialSettings)
        {
            _merchantCredentialSettings = merchantCredentialSettings;
            _oauthtoken = new OAuthToken(_merchantCredentialSettings);
        }
        #endregion
    }
}
