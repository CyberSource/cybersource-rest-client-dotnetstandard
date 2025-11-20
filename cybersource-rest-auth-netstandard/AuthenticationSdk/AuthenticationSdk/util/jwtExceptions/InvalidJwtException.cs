using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationSdk.util.jwtExceptions
{
    public class InvalidJwtException : Exception
    {
        public InvalidJwtException(string message) : base(message) { }
        public InvalidJwtException(string message, Exception cause) : base(message, cause) { }
    }
}
