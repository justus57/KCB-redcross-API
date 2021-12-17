using KCB_redcross_API.Models;
using Microsoft.AspNetCore.Mvc;
using Nancy.Json;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KCB_redcross_API.Controllers
{
    [ApiController]
    [Route("StatusQuery/V1")]
    public class QueryController : Controller
    {      
        [HttpPost]
        public string StatusQuery([FromBody] statusquerybody statusquery)
        {
            string QueryResponse = null;
            string token = Gettoken();
            token = "Bearer " + token;
            var transactionDate = statusquery.transactionDate;
            var fileName = statusquery.fileName;
            var systemCode = statusquery.systemCode;
            var serviceId = statusquery.serviceId;
            var conversationId = statusquery.conversationId;


            var bodyrequest = new statusquery
            {
                headerquery = new Headerquery
                {
                    conversationId = conversationId,
                    serviceId = serviceId,
                    systemCode = systemCode

                },
                payloadquery = new Payloadquery
                {
                    fileName = fileName,
                    transactionDate = transactionDate
                }
            };
            JavaScriptSerializer js = new JavaScriptSerializer();
            string body = js.Serialize(bodyrequest);

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/query/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", token);
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            QueryResponse = response.Content;
            Console.WriteLine(response.Content);
            StatusReply queryResponse = JsonConvert.DeserializeObject<StatusReply>(QueryResponse);
            var status = queryResponse.status;
            var totalSuccess = queryResponse.totalSuccess;
            var fileNameQuery = queryResponse.fileName;

            return fileNameQuery;
        }
        public static string Gettoken()
        {
            string KCBRESPONSE = null;
            string Username = "REDCROSS101";
            string Password = "1520Suspect6?";
            string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(Username + ":" + Password));
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            string auth = "Basic " + svcCredentials;

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/auth/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Basic UkVEQ1JPU1MxMDE6MTUyMFN1c3BlY3Q2Pw==");
            IRestResponse response = client.Execute(request);
            KCBRESPONSE = response.Content;
            Console.WriteLine(response.Content);

            TokenResponse AccessTokenRequestResponse = JsonConvert.DeserializeObject<TokenResponse>(KCBRESPONSE);
            var Accesstoken = AccessTokenRequestResponse.access_token;

            return Accesstoken;
        }
    }
}
