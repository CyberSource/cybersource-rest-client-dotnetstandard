using System;
using ApiSdk.model;
using ApiSdk.service;
using AuthenticationSdk.core;
using AuthenticationSdk.util;
using NLog;

namespace ApiSdk.controller
{
    /*================================================================================
    * Provides Methods to Make HTTP Requests (GET/POST/PUT/DELETE) to CYBS REST API's
    *===============================================================================*/
    public class APIController
    {
        private readonly Logger _logger;
        private readonly PaymentRequestService _paymentRequestService;

        public APIController(MerchantConfig merchantConfig)
        {
            _logger = LogManager.GetCurrentClassLogger();
            Enumerations.ValidateRequestType(merchantConfig.RequestType);
            Enumerations.SetRequestType(merchantConfig);
            _paymentRequestService = new PaymentRequestService(merchantConfig);
        }

        /**
         * @return a Response object (HTTP Response) for the HTTP GET Request
         * based on the Merchant Configuration passed to the Constructor of ApiController Class
         */
        public Response GetPayment()
        {
            try
            {
                // Call the Service to Get the Response Object
                var response = _paymentRequestService.GetResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                this._logger.Error(e.Message);
                this._logger.Error(e.StackTrace);
                return null;
            }
        }

        /**
         * @return a Response object (HTTP Response) for the HTTP POST Request
         * based on the Merchant Configuration passed to the Constructor of ApiController Class
         */
        public Response PostPayment()
        {
            try
            {
                // Call the Service to Get the Response Object
                var response = _paymentRequestService.PostResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                this._logger.Error(e.Message);
                this._logger.Error(e.StackTrace);
                return null;
            }
        }

        /**
         * @return a Response object (HTTP Response) for the HTTP PUT Request
         * based on the Merchant Configuration passed to the Constructor of ApiController Class
         */
        public Response PutPayment()
        {
            try
            {
                // Call the Service to Get the Response Object
                var response = _paymentRequestService.PutResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                this._logger.Error(e.Message);
                this._logger.Error(e.StackTrace);
                return null;
            }
        }

        /**
         * @return a Response object (HTTP Response) for the HTTP DELETE Request
         * based on the Merchant Configuration passed to the Constructor of ApiController Class
         */
        public Response DeletePayment()
        {
            try
            {
                // Call the Service to Get the Response Object
                var response = _paymentRequestService.DeleteResponse();
                LogResponseDetails(response);

                return response;
            }
            catch (Exception e)
            {
                this._logger.Error(e.Message);
                this._logger.Error(e.StackTrace);
                return null;
            }
        }

        private void LogResponseDetails(Response response)
        {
            _logger.Info("v-c-correlation-id:{0}", response.GetResponseHeaderValue(response.Headers, "v-c-correlation-id"));
            _logger.Info("Response Code:{0}", response.StatusCode);
            _logger.Info("Response Message:{0}", response.Data);
            _logger.Info("Status Information:{0}", response.StatusInfo);
        }
    }
}