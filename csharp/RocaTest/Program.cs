namespace RocaTest
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;

    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.X509;

    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("ROCA detection tool https://github.com/crocs-muni/roca");
            if (args.Length == 0)
            {
                WriteUsage();
                return;
            }

            var argumentParser = new ArgumentParser(args);

            if (argumentParser.ShouldParseDirectory)
            {
                TestDirectories(argumentParser.Verbose, argumentParser.DirectoryNames);
            }

            if (!argumentParser.ShouldParseAllStores)
            {
                if (argumentParser.ShouldParseMyStore)
                {
                    TestStore(argumentParser.Verbose, StoreName.My, StoreLocation.CurrentUser);
                }

                if (argumentParser.ShouldParseRootStore)
                {
                    TestStore(argumentParser.Verbose, StoreName.Root, StoreLocation.CurrentUser);
                }

                return;
            }

            // Check all stores
            foreach (StoreName storeName in Enum.GetValues(typeof(StoreName)))
            {
                TestStore(argumentParser.Verbose, storeName, StoreLocation.CurrentUser);
            }
        }

        /// <summary>
        /// Writes the usage to the console.
        /// </summary>
        private static void WriteUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("RocaTest <directory> Scans a directory for certificates and tests them.");
            Console.WriteLine("RocaTest -my         Scans the personal MY store for vulnerable certificates.");
            Console.WriteLine("RocaTest -root       Scans the personal ROOT store for vulnerable certificates.");
            Console.WriteLine("RocaTest -allstores  Scans all store for vulnerable certificates");
            Console.WriteLine("RocaTest -v          Adds verbose output.");
        }

        /// <summary>
        /// Test all certificate files in directories.
        /// </summary>
        /// <param name="verbose">     
        /// If output should be verbose.
        /// </param>
        /// <param name="directoryNames">
        /// The directory names.
        /// </param>
        private static void TestDirectories(bool verbose, IEnumerable<string> directoryNames)
        {
            foreach (var directoryName in directoryNames)
            {
                Console.WriteLine();
                Console.WriteLine("Checking directory " + directoryName);
                if (!Directory.Exists(directoryName))
                {
                    Console.WriteLine("Directory doesn't exist: " + directoryName);
                    continue;
                }

                foreach (var certFile in Directory.GetFiles(directoryName))
                {
                    var fileBytes = File.ReadAllBytes(certFile);
                    if (TestCert(fileBytes))
                    {
                        Console.WriteLine(
                            certFile + " - contains RSA public key vulnerable to ROCA (CVE-2017-15361)");
                    }
                    else
                    {
                        if (verbose)
                        {
                            Console.WriteLine(certFile + " - Certificate does not contain RSA public key vulnerable to ROCA (CVE-2017-15361)");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Test a certificate for roca.
        /// </summary>
        /// <param name="fileBytes">
        /// The file bytes.
        /// </param>
        /// <returns>
        /// True if vulnerable.
        /// </returns>
        private static bool TestCert(byte[] fileBytes)
        {
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(fileBytes);
            RsaKeyParameters rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
            return RocaTest.IsVulnerable(rsaKeyParameters);
        }

        /// <summary>
        /// The test store.
        /// </summary>
        /// <param name="verbose">
        /// If output should be verbose.
        /// </param>
        /// <param name="name">
        /// The name.
        /// </param>
        /// <param name="location">
        /// The location.
        /// </param>
        private static void TestStore(bool verbose, StoreName name, StoreLocation location)
        {
            Console.WriteLine();
            Console.WriteLine("Checking store \"" + name + "\".");

            var vulnFound = false;
            using (var store = new X509Store(name, location))
            {
                store.Open(OpenFlags.MaxAllowed);
                foreach (var certificate in store.Certificates)
                {
                    var fileBytes = certificate.RawData;
                    if (TestCert(fileBytes))
                    {
                        vulnFound = true;
                        Console.WriteLine(
                            certificate.Subject + " - contains RSA public key vulnerable to ROCA (CVE-2017-15361)");
                    }
                    else
                    {
                        if (verbose)
                        {
                            Console.WriteLine(
                                certificate.Subject
                                + " - Certificate does not contain RSA public key vulnerable to ROCA (CVE-2017-15361)");
                        }
                    }
                }
            }

            if (!vulnFound)
            {
                Console.WriteLine("No vulnerable certificates found in \"" + name + "\" store.");
            }
        }
    }
}
