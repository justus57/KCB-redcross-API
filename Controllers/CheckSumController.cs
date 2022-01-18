using KCB_redcross_API.Models;
using Microsoft.AspNetCore.Mvc;
using Nancy.Json;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KCB_redcross_API.Controllers
{
    [ApiController]
    [Route("Checksum/V1")]
    public class CheckSumController : Controller
    {
        public static object systemCode { get; private set; }
        public static object encryptedFile { get; private set; }
        public string report { get; private set; }
        public static string Fileresponse { get; private set; }
        public static string Accesstoken { get; private set; }

        [HttpPost]
        public string checksumfile([FromBody] checksumBody checksum)
        {
            string fileName = checksum.fileName;
            var systemCode = checksum.systemCode;
            var conversationId = checksum.conversationId;
            var serviceId = checksum.serviceId;
            var encryptedFile = checksum.encryptedFile;
            var fileStream = new FileStream(fileName, FileMode.OpenOrCreate, FileAccess.Read);
            
            //var systemCode = "REDCROSS";
            //var conversationId = "REDCROSS12";
            //var serviceId = "REDCROSS";
            //var encryptedFile = @"C:\Users\Admin2\Downloads\New folder\newbie.txt.asc";
            string dataString = GetChecksumBuffered(fileStream);
            try
            {
                // Create a UnicodeEncoder to convert between byte array and string.
                ASCIIEncoding ByteConverter = new ASCIIEncoding();
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAParameters Key = RSAalg.ExportParameters(true);
                RSAParameters PublicKey = RSAalg.ExportParameters(false);

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, Key);
                string base64 = Convert.ToBase64String(signedData, 0, signedData.Length);

                //coverting private key to string
                string privKey;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, Key);
                    //get the string from the stream
                    privKey = sw.ToString();
                }
                string pubKey;
                {
                    //we need some buffer
                    var sw = new System.IO.StringWriter();
                    //we need a serializer
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //serialize the key into the stream
                    xs.Serialize(sw, PublicKey);
                    //get the string from the stream
                    pubKey = sw.ToString();
                }
                string checksums = Encoding.Default.GetString(originalData);

                var sender = SendChecksum(checksums, base64, serviceId, systemCode, conversationId, fileName);



                // encrypt the data using gpg

                PGPEncryptDecrypt pgp = new PGPEncryptDecrypt();

                string passPhrase = "hello world!";

                //full path to file to encrypt
                string origFilePath = @"C:\Users\Admin2\Downloads\New folder\newbie.txt";
                //folder to store encrypted file
                string encryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";
                //folder to store unencrypted file
                string unencryptedFilePath = @"C:\Users\Admin2\Downloads\New folder\";
                //path to public key file 
                string publicKeyFile = @"C:\Users\Admin2\Downloads\New folder\dummy.pkr";
                //path to private key file (this file should be kept at client, AND in a secure place, far from prying eyes and tinkering hands)
                string privateKeyFile = @"C:\Users\Admin2\Downloads\New folder\dummy.skr";

                pgp.Encrypt(origFilePath, publicKeyFile, encryptedFilePath);
                // pgp.Decrypt(encryptedFilePath + "credentials.txt.asc", privateKeyFile, passPhrase, unencryptedFilePath);

                var sendfile = sendingFile();

                filesending Response = JsonConvert.DeserializeObject<filesending>(sendfile);
                var filestatus = Response.status;
                var report = Response.report;
            }
            catch (Exception es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();
            }
            
            return report;
        }
        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)

        {
            try
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA256 to specify the hashing algorithm.
                return RSAalg.SignData(DataToSign, SHA256.Create());
            }
            catch (CryptographicException es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();

                return null;
            }
        }
        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
            }
            catch (CryptographicException es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();

                return false;
            }
        }
        private static string GetChecksumBuffered(Stream stream)
        {
            using (var bufferedStream = new BufferedStream(stream, 1024 * 32))
            {
                var sha = new SHA256Managed();
                byte[] checksum = sha.ComputeHash(bufferedStream);
                return BitConverter.ToString(checksum).Replace("-", String.Empty);

            }
        }
        //Sending the file
        public static string sendingFile()
        {
            try
            {
                string Fileresponse = null;
                string token = Gettoken();
                token = "Bearer " + token;

                var client = new RestClient("https://196.216.223.2:4450/kcb/fileUpload/v1");
                client.Timeout = -1;
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/json");
                request.AddHeader("Authorization", token);
                request.AlwaysMultipartFormData = true;
                request.AddParameter("file", encryptedFile);
                request.AddParameter("SystemCode", systemCode);
                IRestResponse response = client.Execute(request);
                Fileresponse = response.Content;
               
            }
            catch(Exception es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();
            }

            return Fileresponse;
        }
        //Get token from KCB
        public static string Gettoken()
        {
            try
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
                request.AddHeader("Authorization", auth);
                IRestResponse response = client.Execute(request);
                KCBRESPONSE = response.Content;
                

                TokenResponse AccessTokenRequestResponse = JsonConvert.DeserializeObject<TokenResponse>(KCBRESPONSE);
                var Accesstoken = AccessTokenRequestResponse.access_token;
            }catch(Exception es)
            {
                WebService.WriteLog(es.Message);
                string innerEx = "";
                if (es.InnerException != null)
                    innerEx = es.InnerException.ToString();
            }
            return Accesstoken;
        }
        // send Signed Check sum
        public static string SendChecksum(string checksum, string signature, string serviceId, string systemCode, string conversationId, string fileName)
        {
            string CheckSumResponse = null;
            string token = Gettoken();
            token = "Bearer " + token;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var bodyRequest = new Sendchecksum
            {
                header = new Header
                {
                    conversationId = conversationId,
                    serviceId = serviceId,
                    systemCode = systemCode
                },
                payload = new Payload
                {
                    fileName = fileName,
                    checksum = checksum,
                    signature = signature
                }
            };
            JavaScriptSerializer js = new JavaScriptSerializer();
            string body = js.Serialize(bodyRequest);

            var client = new RestClient("https://196.216.223.2:4450/kcb/payments/validation/v1");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", token);
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            CheckSumResponse = response.Content;
           

            checksumresponseBody RequestResponse = JsonConvert.DeserializeObject<checksumresponseBody>(CheckSumResponse);
            var status = RequestResponse.status;
            var description = RequestResponse.description;
            var ConversationId = RequestResponse.conversationId;
            var FileName = RequestResponse.fileName;
            var originatorConversationId = RequestResponse.originatorConversationId;
            var Status = RequestResponse.status;
            var submissionDate = RequestResponse.submissionDate;
            var totalFailed = RequestResponse.totalFailed;
            var totalNumberInFile = RequestResponse.totalNumberInFile;
            var totalSuccess = RequestResponse.totalSuccess;
            var transactionDate = RequestResponse.transactionDate;

            return description;
        }
       
    }
    public class PGPEncryptDecrypt
    {

        public PGPEncryptDecrypt()
        {

        }

        /**
        * A simple routine that opens a key ring file and loads the first available key suitable for
        * encryption.
        *
        * @param in
        * @return
        * @m_out
        * @
        */
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //
            //
            // iterate through the key rings.
            //
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {

                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {

                    if (k.IsEncryptionKey)
                    {

                        return k;

                    }


                }


            }

            throw new ArgumentException("Can't find encryption key in key ring.");

        }

        /**
        * Search a secret key ring collection for a secret key corresponding to
        * keyId if it exists.
        *
        * @param pgpSec a secret key ring collection.
        * @param keyId keyId we want.
        * @param pass passphrase to decrypt secret key with.
        * @return
        */
        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {

            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {

                return null;

            }

            return pgpSecKey.ExtractPrivateKey(pass);

        }

        /**
        * decrypt the passed in message stream
        */
        private static void DecryptFile(Stream inputStream, Stream keyIn, char[] passwd, string defaultFileName, string pathToSaveFile)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            try
            {

                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;
                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {

                    enc = (PgpEncryptedDataList)o;

                }

                else
                {

                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();

                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(keyIn));
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {

                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);
                    if (sKey != null)
                    {

                        pbe = pked;
                        break;

                    }


                }

                if (sKey == null)
                {

                    throw new ArgumentException("secret key for message not found.");

                }

                Stream clear = pbe.GetDataStream(sKey);
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject message = plainFact.NextPgpObject();
                if (message is PgpCompressedData)
                {

                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                    message = pgpFact.NextPgpObject();

                }

                if (message is PgpLiteralData)
                {

                    PgpLiteralData ld = (PgpLiteralData)message;
                    string outFileName = ld.FileName;
                    if (outFileName.Length == 0)
                    {

                        outFileName = defaultFileName;

                    }

                    Stream fOut = File.Create(pathToSaveFile + outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();

                }

                else if (message is PgpOnePassSignatureList)
                {

                    throw new PgpException("encrypted message contains a signed message - not literal data.");

                }

                else
                {

                    throw new PgpException("message is not a simple encrypted file - type unknown.");

                }

                if (pbe.IsIntegrityProtected())
                {

                    if (!pbe.Verify())
                    {

                        Console.Error.WriteLine("message failed integrity check");

                    }

                    else
                    {

                        Console.Error.WriteLine("message integrity check passed");

                    }


                }

                else
                {

                    Console.Error.WriteLine("no message integrity check");

                }


            }

            catch (PgpException e)
            {

                Console.Error.WriteLine(e);
                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {

                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);

                }


            }


        }

        private static void EncryptFile(Stream outputStream, string fileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {

            if (armor)
            {

                outputStream = new ArmoredOutputStream(outputStream);

            }

            try
            {

                MemoryStream bOut = new MemoryStream();
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(
                comData.Open(bOut),
                PgpLiteralData.Binary,
                new FileInfo(fileName));
                comData.Close();
                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                cPk.AddMethod(encKey);
                byte[] bytes = bOut.ToArray();
                Stream cOut = cPk.Open(outputStream, bytes.Length);
                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();
                if (armor)
                {

                    outputStream.Close();

                }


            }

            catch (PgpException e)
            {

                Console.Error.WriteLine(e);
                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {

                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);

                }


            }


        }

        public void Encrypt(string filePath, string publicKeyFile, string pathToSaveFile)
        {

            Stream keyIn, fos;
            keyIn = File.OpenRead(publicKeyFile);
            string[] fileSplit = filePath.Split('\\');
            string fileName = fileSplit[fileSplit.Length - 1];
            fos = File.Create(pathToSaveFile + fileName + ".asc");
            EncryptFile(fos, filePath, ReadPublicKey(keyIn), true, true);
            keyIn.Close();
            fos.Close();

        }

        public void Decrypt(string filePath, string privateKeyFile, string passPhrase, string pathToSaveFile)
        {

            Stream fin = File.OpenRead(filePath);
            Stream keyIn = File.OpenRead(privateKeyFile);
            DecryptFile(fin, keyIn, passPhrase.ToCharArray(), new FileInfo(filePath).Name + ".out", pathToSaveFile);
            fin.Close();
            keyIn.Close();

        }


    }
}
