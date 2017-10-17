using System;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace RocaTest
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (string certFile in Directory.GetFiles("data"))
            {
                if (TestCert(certFile))
                    Console.WriteLine(certFile + " - contains RSA public key vulnerable to ROCA (CVE-2017-15361)");
                else
                    Console.WriteLine(certFile + " - Certificate does not contain RSA public key vulnerable to ROCA (CVE-2017-15361)");
            }
        }

        static bool TestCert(string certFile)
        {
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(File.ReadAllBytes(certFile));
            RsaKeyParameters rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
            return RocaTest.IsVulnerable(rsaKeyParameters);
        }
    }
}
