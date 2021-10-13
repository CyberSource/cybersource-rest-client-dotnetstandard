using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using ApiSdk.connection;
using ApiSdk.mask;
using ApiSdk.model;
using ApiSdk.util;
using AuthenticationSdk.core;
using NLog;
using static AuthenticationSdk.util.Enumerations;

namespace ApiSdk.service
{
    public class PaymentRequestService
    {
        private readonly string _hostName;
        private readonly string _requestJsonData;
        private readonly Logger _logger = LogManager.GetCurrentClassLogger();
        private readonly Masking _masking = new Masking();
        private readonly MerchantConfig _merchantConfig;
        private readonly IConnection _conn;
        private int _statusCode;
        private Response _response;
        private static Logger logger = LogManager.GetCurrentClassLogger();

        public PaymentRequestService(MerchantConfig merchantConfig)
        {
            _merchantConfig = merchantConfig;
            _hostName = merchantConfig.HostName;
            _requestJsonData = merchantConfig.RequestJsonData;

            var authenticaionType = merchantConfig.AuthenticationType;

            if (string.Equals(authenticaionType, AuthenticationType.HTTP_SIGNATURE.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                _conn = new HTTPConnection();
            }
            else if (string.Equals(authenticaionType, AuthenticationType.JWT.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                _conn = new JWTConnection();
            }
        }

        // Generates the HttpClient Object and using it makes an async GET call to the API server
        public Response GetResponse()
        {
            var client = _conn.GetConnectionForGet(_merchantConfig);
            RunAsyncGet(client, _merchantConfig.RequestTarget, _hostName).Wait();

            return _response;
        }

        // Generates the HttpClient Object and using it makes an async POST call to the API server
        public Response PostResponse()
        {
            if (string.IsNullOrEmpty(_requestJsonData))
            {
                throw new Exception($"{Constants.ErrorPrefix} No Request JSON Data passed to the Service for the POST Call");
            }

            var client = _conn.GetConnectionForPost(_merchantConfig);
            RunAsyncPost(client, _merchantConfig.RequestTarget, _hostName, _requestJsonData).Wait();

            return _response;
        }

        public Response PutResponse()
        {
            if (string.IsNullOrEmpty(_requestJsonData))
            {
                throw new Exception($"{Constants.ErrorPrefix} No Request JSON Data passed to the Service for the PUT Call");
            }

            var client = _conn.GetConnectionForPut(_merchantConfig);
            RunAsyncPut(client, _merchantConfig.RequestTarget, _hostName, _requestJsonData).Wait();
            return _response;
        }

        public Response DeleteResponse()
        {
            var client = _conn.GetConnectionForDelete(_merchantConfig);
            RunAsyncDelete(client, _merchantConfig.RequestTarget, _hostName).Wait();

            return _response;
        }

        // End point of the GET Call to the API server
        public async Task RunAsyncGet(HttpClient client, string getUrlSuffix, string hostName)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {
                var uriString = Constants.HttpsUriPrefix + hostName + getUrlSuffix;

                _logger.Trace("{0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.GetAsync(new Uri(uriString)))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = _masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException e)
                {
                    logger.Error($"{Constants.ErrorPrefix} Network Error: Connection could not be established.");
                    logger.Error(e.StackTrace);
                }
                catch (Exception e)
                {
                    logger.Error(e.Message);
                    logger.Error(e.StackTrace);
                }
            }
        }

        // End point of the POST Call to the API server
        public async Task RunAsyncPost(HttpClient client, string postUrlSuffix, string hostName, string requestJsonData)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {
                var request = requestJsonData;

                _logger.Trace("{0} {1}", "REQUEST BODY ->", _masking.MaskMessage(request));

                var content = new StringContent(request);
                content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

                var uriString = Constants.HttpsUriPrefix + hostName + postUrlSuffix;

                _logger.Trace("{0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.PostAsync(uriString, content))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = _masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException e)
                {
                    logger.Error($"{Constants.ErrorPrefix} Network Error: Connection could not be established.");
                    logger.Error(e.StackTrace);
                }
                catch (Exception e)
                {
                    logger.Error(e.Message);
                    logger.Error(e.StackTrace);
                }
            }
        }

        // End point of the PUT Call to the API server
        public async Task RunAsyncPut(HttpClient client, string putUrlSuffix, string hostName, string requestJsonData)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {
                var request = requestJsonData;

                _logger.Trace("{0} {1}", "REQUEST BODY ->", _masking.MaskMessage(request));

                var content = new StringContent(request);
                content.Headers.ContentType = new MediaTypeHeaderValue(Constants.MediaTypeJson);

                var uriString = Constants.HttpsUriPrefix + hostName + putUrlSuffix;

                _logger.Trace("{0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.PutAsync(uriString, content))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = _masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException e)
                {
                    logger.Error($"{Constants.ErrorPrefix} Network Error: Connection could not be established.");
                    logger.Error(e.StackTrace);
                }
                catch (Exception e)
                {
                    logger.Error(e.Message);
                    logger.Error(e.StackTrace);
                }
            }
        }

        // End point of the DELETE Call to the API server
        public async Task RunAsyncDelete(HttpClient client, string deleteUrlSuffix, string hostName)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            using (client)
            {
                var uriString = Constants.HttpsUriPrefix + hostName + deleteUrlSuffix;

                _logger.Trace("{0} {1}", "URL ->", uriString);

                try
                {
                    using (var response = await client.DeleteAsync(new Uri(uriString)))
                    {
                        _statusCode = (int)(TaskStatus)response.StatusCode;
                        var data = await response.Content.ReadAsStringAsync();
                        var dataMasked = _masking.MaskMessage(data);
                        var headers = response.Headers.ToString();

                        _response = new Response(_statusCode, headers, dataMasked);
                    }
                }
                catch (TaskCanceledException e)
                {
                    logger.Error($"{Constants.ErrorPrefix} Network Error: Connection could not be established.");
                    logger.Error(e.StackTrace);
                }
                catch (Exception e)
                {
                    logger.Error(e.Message);
                    logger.Error(e.StackTrace);
                }
            }
        }
    }
}