using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using AuthenticationSdk.util.jwtExceptions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

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
                // Split on '.' and Base64Url-decode the payload part (index 1).
                // Handles both JWS (3 parts) and JWE (5 parts) compact serializations.
                string payloadJson = JwtCompact.DecodePayload(jwtToken);

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
                // Catch exceptions from payload decoding (e.g., malformed token)
                throw new InvalidJwtException("The provided JWT is malformed.", ex);
            }
        }

        public static IDictionary<string, object> GetJwtHeaders(string jwtToken)
        {
            return JwtCompact.DecodeHeaders(jwtToken);
        }

        /// <summary>
        /// Verifies a JWT token against a public key provided as a JWK string.
        /// </summary>
        /// <param name="jwtValue">The JWT token to verify.</param>
        /// <param name="publicKey">The public key in JWK JSON format.</param>
        /// <returns>Returns true if the token is successfully verified.</returns>
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

                // Step 2: Convert to BouncyCastle public key parameters.
                RsaKeyParameters bcPublicKey = DotNetUtilities.GetRsaPublicKey(rsaParameters);

                // Step 3: Dynamically determine the algorithm from the JWT's header.
                var headers = JwtCompact.DecodeHeaders(jwtValue);
                if (!headers.TryGetValue("alg", out var alg))
                {
                    throw new ArgumentException("JWT header is missing the 'alg' parameter.");
                }

                string algStr = alg as string;
                if (algStr == null)
                {
                    throw new ArgumentException($"JWT header 'alg' must be a string, but found: {alg?.GetType().Name ?? "null"} ({alg}).");
                }

                var supportedRsaAlgorithms = new[] { "RS256", "RS384", "RS512" };
                if (Array.IndexOf(supportedRsaAlgorithms, algStr) < 0)
                {
                    throw new ArgumentException($"The algorithm '{algStr}' in the JWT token is not supported. Only {string.Join(", ", supportedRsaAlgorithms)} are supported.");
                }

                // Step 4: Verify the RS256/RS384/RS512 signature using BouncyCastle.
                // JWS signing input = Base64Url(header) + "." + Base64Url(payload)
                string[] parts = jwtValue.Split('.');
                if (parts.Length < 3)
                {
                    throw new InvalidJwtException("JWT must have at least 3 parts.");
                }

                string signingInput   = parts[0] + "." + parts[1];
                byte[] signingBytes   = Encoding.ASCII.GetBytes(signingInput);
                byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(parts[2]);

                Org.BouncyCastle.Crypto.IDigest digest = algStr switch
                {
                    "RS384" => new Sha384Digest(),
                    "RS512" => new Sha512Digest(),
                    _       => new Sha256Digest()   // RS256 default
                };

                var signer = new RsaDigestSigner(digest);
                signer.Init(false, bcPublicKey);
                signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
                bool valid = signer.VerifySignature(signatureBytes);

                if (!valid)
                {
                    throw new JwtSignatureValidationException("JWT verification failed: signature is invalid.");
                }

                // Step 5: Signature verified successfully.
                return true;
            }
            catch (JwtSignatureValidationException)
            {
                throw;
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
