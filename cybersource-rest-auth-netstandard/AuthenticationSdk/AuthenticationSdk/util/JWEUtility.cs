using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AuthenticationSdk.core;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AuthenticationSdk.util
{
    public static class JWEUtilty
    {
        [Obsolete("This method has been marked as Deprecated and will be removed in coming releases. Use DecryptUsingRSAParameters(RSAParameters, string) instead.", false)]
        public static string DecryptUsingPEM(MerchantConfig merchantConfig, string encodedData)
        {
            RSAParameters rsaParams = Cache.FetchCachedRSAParameters(merchantConfig);
            return DecryptUsingRSAParameters(rsaParams, encodedData);
        }

        public static string DecryptUsingRSAParameters(RSAParameters rsaParameters, string encodedData)
        {
            try
            {
                // Strict mode: validate that the JWE header declares the expected alg and enc
                return DecryptJweCompact(rsaParameters, encodedData, lenient: false);
            }
            catch (FormatException)
            {
                // Lenient fallback: skip header algorithm validation
                // (mirrors the old jose-jwt fallback: JWT.Decode(data, rsa) without specifying algorithms)
                return DecryptJweCompact(rsaParameters, encodedData, lenient: true);
            }
        }

        /// <summary>
        /// Decrypts a JWE compact serialization token using RSA-OAEP or RSA-OAEP-256 + AES-256-GCM
        /// via BouncyCastle.Cryptography — cross-platform, no native OS crypto dependencies.
        /// The OAEP hash digest is selected based on the JWE header's "alg" value:
        ///   - "RSA-OAEP"     → SHA-1   (per RFC 7518 §4.3)
        ///   - "RSA-OAEP-256" → SHA-256 (per RFC 7518 §4.3)
        /// When <paramref name="lenient"/> is false, the protected header's "alg" and "enc"
        /// values are validated to be one of the supported algorithms before decryption.
        /// </summary>
        private static string DecryptJweCompact(RSAParameters rsaParameters, string token, bool lenient = false)
        {
            // JWE compact: header.encryptedKey.iv.ciphertext.tag
            string[] parts = token.Split('.');
            if (parts.Length != 5)
            {
                throw new FormatException("Invalid JWE compact serialization: expected 5 parts.");
            }

            string protectedHeader   = parts[0];
            byte[] encryptedKeyBytes = Base64UrlEncoder.DecodeBytes(parts[1]);
            byte[] ivBytes           = Base64UrlEncoder.DecodeBytes(parts[2]);
            byte[] cipherTextBytes   = Base64UrlEncoder.DecodeBytes(parts[3]);
            byte[] authTagBytes      = Base64UrlEncoder.DecodeBytes(parts[4]);

            // Always parse the JWE protected header to determine the actual algorithms
            string alg = null;
            string enc = null;
            byte[] headerBytes = Base64UrlEncoder.DecodeBytes(protectedHeader);
            string headerJson  = Encoding.UTF8.GetString(headerBytes);
            Dictionary<string, object> headers;
            try
            {
                headers = JsonConvert.DeserializeObject<Dictionary<string, object>>(headerJson);
            }
            catch (Newtonsoft.Json.JsonException ex)
            {
                throw new FormatException("JWE protected header is not a valid JSON object.", ex);
            }
            if (headers != null)
            {
                if (headers.TryGetValue("alg", out object algObj))
                {
                    alg = algObj as string;
                }
                if (headers.TryGetValue("enc", out object encObj))
                {
                    enc = encObj as string;
                }
            }

            // Validate header algorithms when in strict mode
            if (!lenient)
            {
                ValidateJweHeader(headers, alg, enc);
            }

            // Select the OAEP hash digest based on the JWE "alg" header:
            //   RSA-OAEP     → SHA-1   (RFC 7518 §4.3)
            //   RSA-OAEP-256 → SHA-256 (RFC 7518 §4.3)
            IDigest oaepDigest;
            if (string.Equals(alg, "RSA-OAEP", StringComparison.Ordinal))
            {
                oaepDigest = new Sha1Digest();
            }
            else
            {
                // Default to SHA-256 for RSA-OAEP-256 or any unknown algorithm
                oaepDigest = new Sha256Digest();
            }

            // Step 1: Unwrap the CEK using RSA-OAEP / RSA-OAEP-256
            var bcPrivateKey = DotNetUtilities.GetRsaKeyPair(rsaParameters).Private;
            var rsaEngine    = new RsaBlindedEngine();
            var encoding     = new OaepEncoding(rsaEngine, oaepDigest);
            encoding.Init(false, bcPrivateKey);
            byte[] cek = encoding.ProcessBlock(encryptedKeyBytes, 0, encryptedKeyBytes.Length);

            // Step 2: Decrypt the ciphertext using AES-256-GCM
            // GCM AAD is the ASCII bytes of the protected header string (per RFC 7516)
            byte[] aad = Encoding.ASCII.GetBytes(protectedHeader);

            // BouncyCastle GCM: append the 16-byte auth tag to the ciphertext
            byte[] cipherTextWithTag = new byte[cipherTextBytes.Length + authTagBytes.Length];
            Buffer.BlockCopy(cipherTextBytes, 0, cipherTextWithTag, 0, cipherTextBytes.Length);
            Buffer.BlockCopy(authTagBytes,    0, cipherTextWithTag, cipherTextBytes.Length, authTagBytes.Length);

            var keyParam    = new KeyParameter(cek);
            var gcmParams   = new AeadParameters(keyParam, 128, ivBytes, aad);
            var gcmCipher   = new GcmBlockCipher(new AesEngine());
            gcmCipher.Init(false, gcmParams);

            byte[] plainText = new byte[gcmCipher.GetOutputSize(cipherTextWithTag.Length)];
            int len = gcmCipher.ProcessBytes(cipherTextWithTag, 0, cipherTextWithTag.Length, plainText, 0);
            len += gcmCipher.DoFinal(plainText, len);

            return Encoding.UTF8.GetString(plainText, 0, len);
        }

        /// <summary>
        /// Validates that the JWE protected header declares a supported algorithm and encryption method.
        /// Supported alg: RSA-OAEP, RSA-OAEP-256. Supported enc: A256GCM.
        /// Throws FormatException if the values are missing or unsupported.
        /// </summary>
        private static void ValidateJweHeader(Dictionary<string, object> headers, string alg, string enc)
        {
            if (headers == null)
            {
                throw new FormatException("JWE protected header could not be deserialized.");
            }

            if (string.IsNullOrEmpty(alg))
            {
                throw new FormatException("JWE header is missing the 'alg' parameter.");
            }

            var supportedAlgs = new[] { "RSA-OAEP-256", "RSA-OAEP" };
            if (!supportedAlgs.Contains(alg, StringComparer.Ordinal))
            {
                throw new FormatException($"Unexpected JWE algorithm: '{alg}'. Expected '{string.Join("' or '", supportedAlgs)}'.");
            }

            if (string.IsNullOrEmpty(enc))
            {
                throw new FormatException("JWE header is missing the 'enc' parameter.");
            }

            var supportedEncs = new[] { "A256GCM", "A128GCM" };
            if (!supportedEncs.Contains(enc, StringComparer.Ordinal))
            {
                throw new FormatException($"Unexpected JWE encryption: '{enc}'. Expected '{string.Join("' or '", supportedEncs)}'.");
            }
        }

        /// <summary>
        /// Encrypts a byte payload as a JWE compact token using RSA-OAEP-256 + AES-256-GCM
        /// via BouncyCastle.Cryptography — identical output format to jose-jwt JWT.EncodeBytes.
        /// </summary>
        internal static string EncryptJweCompact(byte[] plainTextBytes, RSA rsaPublicKey, string kid)
        {
            // Build the protected header
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var headerObj = new JObject
            {
                ["alg"] = "RSA-OAEP-256",
                ["enc"] = "A256GCM",
                ["kid"] = kid,
                ["iat"] = iat
            };
            string headerJson    = headerObj.ToString(Newtonsoft.Json.Formatting.None);
            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));

            // Step 1: Generate a random 256-bit CEK and 96-bit IV
            byte[] cek = new byte[32];
            byte[] iv  = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(cek);
                rng.GetBytes(iv);
            }

            // Step 2: Wrap the CEK using RSA-OAEP-256 (BouncyCastle)
            var bcPublicKey = DotNetUtilities.GetRsaPublicKey(rsaPublicKey.ExportParameters(false));
            var rsaEngine   = new RsaBlindedEngine();
            var encoding    = new OaepEncoding(rsaEngine, new Sha256Digest());
            encoding.Init(true, bcPublicKey);
            byte[] encryptedKey = encoding.ProcessBlock(cek, 0, cek.Length);

            // Step 3: Encrypt the payload with AES-256-GCM
            // AAD is the ASCII bytes of the Base64Url-encoded protected header (per RFC 7516 §5.1 step 14)
            byte[] aad = Encoding.ASCII.GetBytes(headerEncoded);

            var keyParam  = new KeyParameter(cek);
            var gcmParams = new AeadParameters(keyParam, 128, iv, aad);
            var gcmCipher = new GcmBlockCipher(new AesEngine());
            gcmCipher.Init(true, gcmParams);

            byte[] cipherTextWithTag = new byte[gcmCipher.GetOutputSize(plainTextBytes.Length)];
            int len = gcmCipher.ProcessBytes(plainTextBytes, 0, plainTextBytes.Length, cipherTextWithTag, 0);
            len += gcmCipher.DoFinal(cipherTextWithTag, len);

            // BouncyCastle appends the 16-byte tag at the end — split them out
            int cipherLen = len - 16;
            byte[] cipherText = new byte[cipherLen];
            byte[] authTag    = new byte[16];
            Buffer.BlockCopy(cipherTextWithTag, 0,         cipherText, 0, cipherLen);
            Buffer.BlockCopy(cipherTextWithTag, cipherLen, authTag,    0, 16);

            // Step 4: Assemble the JWE compact serialization
            return headerEncoded
                + "." + Base64UrlEncoder.Encode(encryptedKey)
                + "." + Base64UrlEncoder.Encode(iv)
                + "." + Base64UrlEncoder.Encode(cipherText)
                + "." + Base64UrlEncoder.Encode(authTag);
        }
    }
}
