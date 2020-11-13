using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using NLog;
using NLog.Targets;

namespace AuthenticationSdk.util
{
    public class LogUtility
    {
        private static LogUtility _singletonLogUtility;

        private LogUtility(string enableLog, string logDirectory, string logFileName, string logFileMaxSize)
        {
            // If user does not want logging the EnableLog property can be set to FALSE
            if (string.Equals(enableLog, "FALSE", StringComparison.OrdinalIgnoreCase))
            {
                LogManager.DisableLogging();
            }

            try
            {
                var target = LogManager.Configuration.FindTargetByName("file") as FileTarget;

                if (target != null)
                {
                    // using the log path set by the merchant, if not set, using default value set in NLog.config
                    if (!string.IsNullOrEmpty(logDirectory))
                    {
                        target.FileName = logDirectory + @"\" + logFileName;
                    }

                    // set the maximum allowed size of the log file
                    if (!string.IsNullOrEmpty(logFileMaxSize))
                    {
                        target.ArchiveAboveSize = long.Parse(logFileMaxSize);
                    }
                }
                else
                {
                    throw new Exception($"{Constants.ErrorPrefix} No Target with the name 'file' found in NLog.config");
                }
            }
            catch (NullReferenceException)
            {
                // If no nlog configuration  (NLog.config file) found
                LogManager.DisableLogging();
            }
        }

        public static void InitLogConfig(string enableLog, string logDirectory, string logFileName, string logFileMaxSize)
        {
            if (!string.Equals(enableLog, "true", StringComparison.OrdinalIgnoreCase))
            {
                enableLog = "FALSE";
            }

            if (_singletonLogUtility == null)
            {
                _singletonLogUtility = new LogUtility(enableLog, logDirectory, logFileName, logFileMaxSize);
            }
        }
    }
}
