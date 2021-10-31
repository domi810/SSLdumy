using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLdumy
{
    class Program
    {
        // Domain name for which to perform certificate pinning
        private const string DomainName = "self-signed.badssl.com";

        // Encoded RSAPublicKey for Domain name
        private const string DomainPublicKey = "3082010A0282010100C204ECF88CEE04C2B3D850D57058CC9318EB5CA86849B022B5F9959EB12B2C763E6CC04B604C4CEAB2B4C00F80B6B0F972C98602F95C415D132B7F71C44BBCE9942E5037A6671C618CF64142C546D31687279F74EB0A9D11522621736C844C7955E4D16BE8063D481552ADB328DBAAFF6EFF60954A776B39F124D131B6DD4DC0C4FC53B96D42ADB57CFEAEF515D23348E72271C7C2147A6C28EA374ADFEA6CB572B47E5AA216DC69B15744DB0A12ABDEC30F47745C4122E19AF91B93E6AD2206292EB1BA491C0C279EA3FB8BF7407200AC9208D98C5784538105CBE6FE6B5498402785C710BB7370EF6918410745557CF9643F3D2CC3A97CEB931A4C86D1CA850203010001";
        static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();
            string[] endpoints;
            try
            {
                endpoints = System.IO.File.ReadAllLines(@"endpoints.txt");
            }
            catch (Exception ex)
            {
                Log.Fatal(ex.Message);
                Console.ReadLine();
                return;
            }
            
            Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();


            foreach (var endpoint in endpoints)
            {
                using (var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = PinPublicKey
                })
                {
                    using (var client = new HttpClient(handler))
                    {
                        try
                        {
                            Log.Information("Endpoint: " + endpoint);
                            var result = client.GetAsync(endpoint);
                            Log.Information("Result: " + result.Result.StatusCode);
                        }
                        catch (Exception ex)
                        {

                            Log.Error("Error: " + ex.InnerException);
                        }
                        finally
                        {
                            Console.WriteLine(System.Environment.NewLine + "******************************************************************************************************************" + System.Environment.NewLine);
                        }
                    }
                }

            }
            Console.ReadLine();
        }
        //https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
        private static bool PinPublicKey(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate == null)
                return false;

            // if the request is for the target domain, perform certificate pinning
            if (string.Equals(requestMessage.RequestUri.Authority, DomainName, StringComparison.OrdinalIgnoreCase))
            {
                var pk = certificate.GetPublicKeyString();
                return pk.Equals(DomainPublicKey);
            }

            //Check whether there were any policy errors for any other domain
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    }
}
