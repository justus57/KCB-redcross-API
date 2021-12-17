using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KCB_redcross_API.Models
{
    public class checksumBody
    {
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }
        public string fileName { get; set; }
        public string encryptedFile { get; set; }
        public string fileStream { get; set; }
    }
    public class TokenResponse
    {
        public string access_token { get; set; }
        public string expires_in { get; set; }
        public string refresh_token { get; set; }
        public string token_type { get; set; }
        public string scope { get; set; }
    }
    public class checksumresponseBody
    {
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }

    }
    public class Sendchecksum
    {
        public Header header { get; set; }
        public Payload payload { get; set; }
    }
    public class Header
    {
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }


    }
    public class Payload
    {
        public string checksum { get; set; }
        public string signature { get; set; }
        public string fileName { get; set; }


    }
    public class filesending
    {
        public string checksum { get; set; }
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }
        public string report { get; set; }

    }
    public class statusquery
    {
        public Headerquery headerquery { get; set; }
        public Payloadquery payloadquery { get; set; }
    }
    public class Headerquery
    {
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }
    }
    public class Payloadquery
    {
        public string fileName { get; set; }
        public string transactionDate { get; set; }
    }
    public class StatusReply
    {
        public int status { get; set; }
        public string description { get; set; }
        public string conversationId { get; set; }
        public string originatorConversationId { get; set; }
        public string fileName { get; set; }
        public string checksum { get; set; }
        public DateTime transactionDate { get; set; }
        public DateTime submissionDate { get; set; }
        public int totalNumberInFile { get; set; }
        public int totalSuccess { get; set; }
        public int totalFailed { get; set; }
        public string statusquery { get; set; }
    }
    public class statusquerybody
    {
        public string fileName { get; set; }
        public string transactionDate { get; set; }
        public string conversationId { get; set; }
        public string serviceId { get; set; }
        public string systemCode { get; set; }
    }
}
