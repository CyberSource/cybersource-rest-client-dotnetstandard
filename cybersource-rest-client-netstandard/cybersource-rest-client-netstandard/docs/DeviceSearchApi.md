# CyberSource.Api.DeviceSearchApi

All URIs are relative to *https://apitest.cybersource.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**PostSearchQueryV3**](DeviceSearchApi.md#postsearchqueryv3) | **POST** /dms/v3/devices/search | Retrieve List of Devices for a given search query V3


<a name="postsearchqueryv3"></a>
# **PostSearchQueryV3**
> InlineResponse2006 PostSearchQueryV3 (PostDeviceSearchRequestV3 postDeviceSearchRequestV3)

Retrieve List of Devices for a given search query V3

Search for devices matching a given search query.  The search query supports serialNumber, readerId, terminalId, status, statusChangeReason or organizationId  Matching results are paginated. 

### Example
```csharp
using System;
using System.Diagnostics;
using CyberSource.Api;
using CyberSource.Client;
using CyberSource.Model;

namespace Example
{
    public class PostSearchQueryV3Example
    {
        public void main()
        {
            var apiInstance = new DeviceSearchApi();
            var postDeviceSearchRequestV3 = new PostDeviceSearchRequestV3(); // PostDeviceSearchRequestV3 | 

            try
            {
                // Retrieve List of Devices for a given search query V3
                InlineResponse2006 result = apiInstance.PostSearchQueryV3(postDeviceSearchRequestV3);
                Debug.WriteLine(result);
            }
            catch (Exception e)
            {
                Debug.Print("Exception when calling DeviceSearchApi.PostSearchQueryV3: " + e.Message );
            }
        }
    }
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **postDeviceSearchRequestV3** | [**PostDeviceSearchRequestV3**](PostDeviceSearchRequestV3.md)|  | 

### Return type

[**InlineResponse2006**](InlineResponse2006.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json;charset=UTF-8
 - **Accept**: application/json;charset=UTF-8

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

