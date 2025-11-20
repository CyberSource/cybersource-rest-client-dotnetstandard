using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationSdk.util.jwtExceptions
{
    public class InvalidJwkException : Exception
    {
        public InvalidJwkException(string message) : base(message) { }
        public InvalidJwkException(string message, Exception cause) : base(message, cause) { }
    }
}
