using System;
using System.IO;
using AuthenticationSdk.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AuthenticationSdkTests.NetCore.util
{
    [TestClass]
    public class CacheTests
    {
        private static readonly string ResourceDir =
            Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "Resource"));

        [TestMethod]
        public void FetchCachedCertificate_WrongPassword_DoesNotLeakPasswordInException()
        {
            string sourceP12 = Path.Combine(ResourceDir, "testrest.p12");
            string tempP12 = Path.Combine(Path.GetTempPath(), $"aisast10825_{Guid.NewGuid():N}.p12");
            string attemptedPassword = "SuperSecret_10825!";

            File.Copy(sourceP12, tempP12, true);

            try
            {
                var ex = Assert.ThrowsException<Exception>(() => Cache.FetchCachedCertificate(tempP12, attemptedPassword));

                Assert.IsFalse(ex.Message.Contains(attemptedPassword), "Exception message leaked key password.");
                Assert.IsFalse(ex.Message.Contains("KeyPassword provided:"), "Exception message still uses old leaking format.");
            }
            finally
            {
                if (File.Exists(tempP12))
                {
                    File.Delete(tempP12);
                }
            }
        }
    }
}
