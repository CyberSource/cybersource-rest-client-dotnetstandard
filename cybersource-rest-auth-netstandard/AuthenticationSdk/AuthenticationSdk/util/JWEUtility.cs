using Jose;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using AuthenticationSdk.core;

namespace AuthenticationSdk.util
{
    public static class JWEUtilty
    {
        private static string LoadKeyFromFile(string path)
        {
            return File.ReadAllText(path);
        }

        public static string DecryptUsingPEM(MerchantConfig merchantConfig, string encodedData)
        {
            var privateKey = LoadKeyFromFile(merchantConfig.PemFileDirectory);
            PemReader pemReader = new PemReader(new StringReader(privateKey));
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);
            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);
            return JWT.Decode(encodedData, rsa, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);
        }
    }
}
