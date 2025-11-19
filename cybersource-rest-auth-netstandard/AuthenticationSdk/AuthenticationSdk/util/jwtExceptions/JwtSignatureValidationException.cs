using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationSdk.util.jwtExceptions
{
    public class JwtSignatureValidationException : Exception
    {
        public JwtSignatureValidationException(string message) : base(message) { }
        public JwtSignatureValidationException(string message, Exception cause) : base(message, cause) { }
    }
}
