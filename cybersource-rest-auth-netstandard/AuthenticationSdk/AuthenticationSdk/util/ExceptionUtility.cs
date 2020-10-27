using NLog;

namespace AuthenticationSdk.util
{
    public class ExceptionUtility
    {
        private static bool _exceptionIsCaughtAlready;

        public static void Exception(string exceptionMessage, string stackTrace)
        {
            var logger = LogManager.GetCurrentClassLogger();

            if (!_exceptionIsCaughtAlready)
            {
                if (!string.IsNullOrEmpty(exceptionMessage))
                {
                    logger.Error(exceptionMessage);

                    if (!string.IsNullOrEmpty(stackTrace))
                    {
                        logger.Trace(stackTrace);
                    }
                }

                _exceptionIsCaughtAlready = true;
            }
        }
    }
}