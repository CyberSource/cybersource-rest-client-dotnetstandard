using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Jose;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using AuthenticationSdk.util.jwtExceptions;

namespace AuthenticationSdk.util
{
    public static class JWTUtility
    {


        /// <summary>
        /// Parses a JWT token to verify its structure and decodes its payload, without performing signature validation.
        /// This is useful for inspecting the token's claims before verifying its authenticity.
        /// </summary>
        /// <param name="jwtToken">The JWT token string to parse.</param>
        /// <returns>The JSON payload of the token as a string if the token is structurally valid.</returns>
        /// <exception cref="ArgumentException">Thrown if the token is null, empty, malformed, or not a valid JWT structure.</exception>
        public static string Parse(string jwtToken)
        {
            if (string.IsNullOrWhiteSpace(jwtToken))
            {
                throw new InvalidJwtException("JWT token cannot be null, empty, or whitespace.");
            }

            try
            {
                // The jose-jwt library's Payload method handles splitting the token and Base64Url decoding the payload part.
                // It will throw an exception if the token does not have three parts or if the payload is not valid Base64Url.
                string payloadJson = JWT.Payload(jwtToken);

                // The JWT specification requires the payload (Claims Set) to be a JSON object.
                // We'll verify this to ensure the token is fully compliant.
                try
                {
                    JsonConvert.DeserializeObject(payloadJson);
                }
                catch (JsonException jsonEx)
                {
                    throw new JsonException("Invalid JWT: The payload is not a valid JSON object.", jsonEx);
                }

                // If all checks pass, return the decoded payload.
                return payloadJson;
            }
            catch (JsonException)
            {
                // Rethrow JSON exceptions as they are.
                throw;
            }
            catch (Exception ex)
            {
                // Catch exceptions from JWT.Payload() (e.g., malformed token)
                throw new InvalidJwtException("The provided JWT is malformed.", ex);
            }
        }

        public static IDictionary<string, object> GetJwtHeaders(string jwtToken)
        {
            return JWT.Headers(jwtToken);
        }

        /// <summary>
        /// Verifies a JWT token against a public key provided as a JWK string.
        /// </summary>
        /// <param name="jwtValue">The JWT token to verify.</param>
        /// <param name="publicKey">The public key in JWK JSON format.</param>
        /// <returns>Returns true if the token is successfully verified.</returns>
        /// <exception cref="Exception">
        /// Throws an exception if verification fails due to an invalid signature,
        /// a malformed token, a missing algorithm header, or other errors.
        /// </exception>
        /// <exception cref="JwtSignatureValidationException">
        /// Thrown if verification fails due to an invalid signature, malformed token, missing algorithm header, or other errors.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if the JWT header is missing the 'alg' parameter or the algorithm is not supported.
        /// </exception>
        /// <exception cref="InvalidJwkException">
        /// Thrown if the JWK is invalid, not an RSA key, or missing required fields.
        /// </exception>
        public static bool VerifyJwt(string jwtValue, string publicKey)
        {
            try
            {
                // Step 1: Convert the JWK string into RSA parameters.
                RSAParameters rsaParameters = ConvertJwkToRsaParameters(publicKey);

                // Step 2: Create an RSACryptoServiceProvider and import the public key.
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);

                // Step 3: Dynamically determine the algorithm from the JWT's header.
                var headers = JWT.Headers(jwtValue);
                if (!headers.TryGetValue("alg", out var alg))
                {
                    throw new ArgumentException("JWT header is missing the 'alg' parameter.");
                }

                string algStr = alg as string;
                var supportedRsaAlgorithms = new[] { "RS256", "RS384", "RS512" };
                if (Array.IndexOf(supportedRsaAlgorithms, algStr) < 0)
                {
                    throw new ArgumentException($"The algorithm in the JWT token is not RSA. Only {string.Join(", ", supportedRsaAlgorithms)} are supported.");
                }

                // Parse the string algorithm into the JwsAlgorithm enum.
                var jwsAlgorithm = (JwsAlgorithm)Enum.Parse(typeof(JwsAlgorithm), algStr);

                // Step 4: Decode and verify the token.
                // The JWT.Decode method will perform signature validation and throw
                // a Jose.IntegrityException if the signature is invalid.
                JWT.Decode(jwtValue, rsa, jwsAlgorithm);

                // Step 5: If JWT.Decode completes without throwing an exception, verification is successful.
                return true;
            }
            catch (JoseException ex)
            {
                // This will catch signature validation errors (IntegrityException)
                // or other JWT-specific issues from the jose-jwt library.
                // Re-throwing as a general exception to signal verification failure.
                throw new JwtSignatureValidationException("JWT verification failed. See inner exception for details.", ex);
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (InvalidJwkException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // This catches other potential errors, such as from JWK conversion or invalid algorithm parsing.
                throw new JwtSignatureValidationException("An unexpected error occurred during JWT verification.", ex);
            }
        }

        /// <summary>
        /// Converts a JSON Web Key (JWK) string into RSAParameters.
        /// This method is designed for RSA public keys.
        /// </summary>
        /// <param name="jwkJson">The JWK in JSON string format.</param>
        /// <returns>An RSAParameters object containing the public key.</returns>
        /// <exception cref="InvalidJwkException">
        /// Thrown if the JWK is invalid, not an RSA key, or missing required fields.
        /// </exception>
        private static RSAParameters ConvertJwkToRsaParameters(string jwkJson)
        {
            Dictionary<string, string> jwk;
            try
            {
                jwk = JsonConvert.DeserializeObject<Dictionary<string, string>>(jwkJson);
            }
            catch (JsonException ex)
            {
                throw new InvalidJwkException("Malformed JWK: Not valid JSON format", ex);
            }

            if (jwk == null || !jwk.ContainsKey("kty") || jwk["kty"] != "RSA" || !jwk.ContainsKey("n") || !jwk.ContainsKey("e"))
            {
                throw new InvalidJwkException("Invalid JWK: Must be an RSA key with 'kty', 'n', and 'e' values.");
            }

            // Use the standard library for Base64Url decoding
            byte[] modulus = Base64UrlEncoder.DecodeBytes(jwk["n"]);
            byte[] exponent = Base64UrlEncoder.DecodeBytes(jwk["e"]);

            return new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent
            };
        }
    }
}
