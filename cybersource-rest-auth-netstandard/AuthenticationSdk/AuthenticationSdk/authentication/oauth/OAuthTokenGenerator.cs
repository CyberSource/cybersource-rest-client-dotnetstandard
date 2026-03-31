using System;
using System.Collections.Generic;
using System.Text;
using AuthenticationSdk.core;

namespace AuthenticationSdk.authentication.oauth
{
    public class OAuthTokenGenerator : ITokenGenerator
    {
        private readonly MerchantConfig _merchantConfig;
        private readonly OAuthToken _oauthtoken;

        public OAuthTokenGenerator(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            _oauthtoken = new OAuthToken(_merchantConfig);
        }

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
    }
}
