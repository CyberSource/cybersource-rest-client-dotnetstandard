using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthenticationSdk.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NLog;

namespace AuthenticationSdkTests.NetCore
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void SingleThreadedLogging()
        {
            string result = LogUtility.MaskSensitiveData("foo");

            Assert.AreEqual("foo", result);

        }


        /// <summary>
        /// Ensure that MaskSensitive Data is thread safe
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public async Task MultiThreadedLogging()
        {
            int taskCount = 100;

            List<Task> tasks = new List<Task>();
            for (int i = 0; i < taskCount; i++)
            {
                tasks.Add(new Task(() =>
                {
                    for (int j = 0; j < 100; j++)
                    {
                        var r = LogUtility.MaskSensitiveData("foo");
                        Assert.AreEqual("foo", r);
                    }
                }));
            }

            foreach(var task in tasks)
            {
                task.Start();
            }

            await Task.WhenAll(tasks);
        }


        /// <summary>
        /// Ensure IsMaskingEnabled does not throw exceptions
        /// </summary>
        [TestMethod]
        public void MaskSenstiveDataSetting()
        {
            Assert.IsTrue(LogUtility.IsMaskingEnabled(LogManager.GetCurrentClassLogger()));
        }
    }
}
