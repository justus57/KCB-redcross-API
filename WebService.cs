﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace KCB_redcross_API
{
    class WebService
    {
        static string path = AppDomain.CurrentDomain.BaseDirectory + @"\Config.xml";
        // static string connectionstring = null;
        static string UserName = null;
        static string Password = null;
        static string NAVWebService = null;
        static string IsPasswordEncrypted = null;

        public static void GetServiceConstants()
        {
            NAVWebService = GetConfigData("NavWebService");
            UserName = GetConfigData("Username");
            Password = GetConfigData("Password");
            //IsPasswordEncrypted = GetConfigData("IsEncrypted");
            ////  connectionstring = GetConfigData("ConnectionString");

            //if (IsPasswordEncrypted == "N")
            //{
            //    string EncryptedPassword = EncryptDecrypt.Encrypt(Password, true);
            //    //updateConfig
            //    UpDateConfig(NAVWebService, "Settings/NavWebService");
            //    // UpDateConfig(connectionstring, "Settings/ConnectionString");
            //    UpDateConfig("Y", "Settings/IsEncrypted");
            //    UpDateConfig(EncryptedPassword, "Settings/Password");
            //}
            //else if (IsPasswordEncrypted == "Y")
            //{
            //    Password = EncryptDecrypt.Decrypt(Password, true);
            //}
        }

        private static void UpDateConfig(string Value, string XMLNode)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(path);
                doc.SelectSingleNode(XMLNode).InnerText = Value;

                doc.Save(path); //This will save the changes to the file.
            }
            catch (Exception es)
            {
                WriteLog(es.Message);
            }
        }
        public static string GetConfigData(string XMLNode)
        {
            string value = "";
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(path);
                XmlNode WebServiceNameNode = doc.GetElementsByTagName(XMLNode)[0];

                value = WebServiceNameNode.InnerText;
            }
            catch (Exception es)
            {
                WriteLog(es.Message);
            }
            return value;
        }

        public static void WriteLog(string text)
        {
            try
            {
                //set up a filestream
                string strPath = @"C:\Logs\KCBAPI";
                string fileName = DateTime.Now.ToString("MMddyyyy") + "_logs.txt";
                string filenamePath = strPath + '\\' + fileName;
                Directory.CreateDirectory(strPath);
                FileStream fs = new FileStream(filenamePath, FileMode.OpenOrCreate, FileAccess.Write);
                //set up a streamwriter for adding text
                StreamWriter sw = new StreamWriter(fs);
                //find the end of the underlying filestream
                sw.BaseStream.Seek(0, SeekOrigin.End);
                //add the text
                sw.WriteLine(DateTime.Now.ToString() + " : " + text);
                //add the text to the underlying filestream
                sw.Flush();
                //close the writer
                sw.Close();
            }
            catch (Exception ex)
            {
                //throw;
                ex.Data.Clear();
            }
        }

       
    }
}
