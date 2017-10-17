using System;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using iTextSharp.text.pdf;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;

namespace RocaTest
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (string certFile in Directory.GetFiles("data")) {
                if (certFile.EndsWith(".pdf")) {
                    TestPDF(certFile);
                } else {
                    if (certFile.EndsWith(".pem")) {
                        Console.WriteLine(certFile + " - contains RSA public key vulnerable to ROCA (CVE-2017-15361)");
                    } else {
                        Console.WriteLine(certFile + " - Certificate does not contain RSA public key vulnerable to ROCA (CVE-2017-15361)");
                    }
                }
                Console.ReadLine();
            }
        }
        static void TestPDF(string path)
        {
            Console.WriteLine("processing PDF");
            AcroFields acroFields = new PdfReader(path).AcroFields;
            List<string> names = acroFields.GetSignatureNames();
            foreach (var name in names) {
                try {

                    Console.WriteLine(name);
                    PdfDictionary dict = acroFields.GetSignatureDictionary(name);

                    PdfString contents = (PdfString)PdfReader.GetPdfObject(dict.Get(PdfName.CONTENTS));


                    byte[] PKCS7 = contents.GetOriginalBytes();
                    var signedData = new SignedCms();
                    signedData.Decode(PKCS7);
                    Console.WriteLine(signedData.Certificates.Count);
                    int i = 0;
                    foreach (var certificate in signedData.Certificates) {
                        i++;

                        X509CertificateParser x509CertificateParser = new X509CertificateParser();
                        X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(certificate.GetRawCertData());
                        RsaKeyParameters rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
                        if (RocaTest.IsVulnerable(rsaKeyParameters)) {
                            Console.WriteLine("Cetificate #" + i + " is vulnerable. Cert Hash: " + certificate.GetCertHashString());
                        } else {
                            Console.WriteLine("Cetificate #" + i + " is NOT vulnerable");
                        }
                    }
                } catch (Exception exc) {
                    Console.WriteLine(exc.Message);
                }
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
