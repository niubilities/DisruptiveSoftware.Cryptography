namespace DisruptiveSoftware.Cryptography.Utils
{
    using System.Reflection;
    using System.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using DisruptiveSoftware.Cryptography.Extensions;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.Sec;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Utilities;
    using Org.BouncyCastle.X509;
    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public static class CertificateUtils
    {
        static SecureRandom secureRandom = new SecureRandom();

        static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var keygenParam = new KeyGenerationParameters(secureRandom, length);

            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName)
        {
            var ecParam = SecNamedCurves.GetByName(curveName);
            var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
            var keygenParam = new ECKeyGenerationParameters(ecDomain, secureRandom);

            var keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(keygenParam);
            return keyGenerator.GenerateKeyPair();
        }

        static X509Certificate GenerateCertificate(
            X509Name issuer, X509Name subject,
            AsymmetricKeyParameter issuerPrivate,
            AsymmetricKeyParameter subjectPublic)
        {
            ISignatureFactory signatureFactory;
            if (issuerPrivate is ECPrivateKeyParameters)
            {
                signatureFactory = new Asn1SignatureFactory(
                    X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                    issuerPrivate);
            }
            else
            {
                signatureFactory = new Asn1SignatureFactory(
                    PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                    issuerPrivate);
            }

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuer);
            certGenerator.SetSubjectDN(subject);
            certGenerator.SetSerialNumber(BigInteger.ValueOf(1));
            certGenerator.SetNotAfter(DateTime.UtcNow.AddHours(1));
            certGenerator.SetNotBefore(DateTime.UtcNow);
            certGenerator.SetPublicKey(subjectPublic);
            return certGenerator.Generate(signatureFactory);
        }

        static bool ValidateSelfSignedCert(Org.BouncyCastle.X509.X509Certificate cert, ICipherParameters pubKey)
        {
            cert.CheckValidity(DateTime.UtcNow);
            var tbsCert = cert.GetTbsCertificate();
            var sig = cert.GetSignature();

            var signer = SignerUtilities.GetSigner(cert.SigAlgName);
            signer.Init(false, pubKey);
            signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
            return signer.VerifySignature(sig);
        }
        //Sorry this code does not write the private key output to files. It will be stored in caKey and eeKey.
        //If you want to write pfx to file, you'll need to use Pkcs12Store and give the password to Save method.
        static void Main(string[] args)
        {
            var caName = new X509Name("CN=TestCA");
            var eeName = new X509Name("CN=TestEE");
            var caKey = GenerateEcKeyPair("secp256r1");
            var eeKey = GenerateRsaKeyPair(2048);

            var caCert = GenerateCertificate(caName, caName, caKey.Private, caKey.Public);
            var eeCert = GenerateCertificate(caName, eeName, caKey.Private, eeKey.Public);
            var caOk = ValidateSelfSignedCert(caCert, caKey.Public);
            var eeOk = ValidateSelfSignedCert(eeCert, caKey.Public);
             

            using (var f = File.OpenWrite("ca.cer"))
            {
                var buf = caCert.GetEncoded();
                f.Write(buf, 0, buf.Length);
            }

            using (var f = File.OpenWrite("ee.cer"))
            {
                var buf = eeCert.GetEncoded();
                f.Write(buf, 0, buf.Length);
            }



            //save as pfx

             
// Stage One - Create a Certificate

            // Random number generators
            var _randomGenerator = new CryptoApiRandomGenerator();
            var _random = new SecureRandom(_randomGenerator);

            // Create a bouncy certificate generator
            var _certificateGenerator = new X509V3CertificateGenerator();

            // Create a random serial number compliant with 
            var _serialNumber =
                BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), _random);
            _certificateGenerator.SetSerialNumber(_serialNumber);

            // Define signature algorithm
            const string _signatureAlgorithm = "SHA256WithRSA";
            _certificateGenerator.SetSignatureAlgorithm(_signatureAlgorithm);

            // Define the subject name
            string _subjectName = "C=ZA,O=SALT Africa,OU=Cloud Services,CN=Password Client";

            // Define the subject DN
            //  because its self signed lets set the issuer as the subject 
            var _subjectDN = new X509Name(_subjectName);
            var _issuerDN = _subjectDN;

            // Update the certificate generator with the Issuer and Subject DN
            _certificateGenerator.SetIssuerDN(_issuerDN);
            _certificateGenerator.SetSubjectDN(_subjectDN);

            // Define certificate validity
            var _notBefore = DateTime.UtcNow.Date;
            var _notAfter = _notBefore.AddYears(5);

            // Update the certificate generator with certificate validity
            _certificateGenerator.SetNotBefore(_notBefore);
            _certificateGenerator.SetNotAfter(_notAfter);

            // Define the strength of the Key Pair
            const int strength = 2048;
            var _keyGenerationParameters = new KeyGenerationParameters(_random, strength);

            // Create a new RSA key 
            var _keyPairGenerator = new RsaKeyPairGenerator();
            _keyPairGenerator.Init(_keyGenerationParameters);
            var _subjectKeyPair = _keyPairGenerator.GenerateKeyPair();

            // Add the public key to the certificate generator
            _certificateGenerator.SetPublicKey(_subjectKeyPair.Public);

            // Add the private key to the certificate generator
            var _issuerKeyPair = _subjectKeyPair;
            var _certificate = _certificateGenerator.Generate(_issuerKeyPair.Private, _random);

            // Stage Two - Convert and add certificate to local certificate store.

            // Bouncy castle does not provide a mechanism to interface with the local certificate store.
            // so we create a PKCS12 store (a .PFX file) in memory, and add the public and private key to that.
            var store = new Pkcs12Store();

            // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
            string friendlyName = _certificate.SubjectDN.ToString();

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(_certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            // Add the private key.
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(_subjectKeyPair.Private), new[] { certificateEntry });

            // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
            const string password = "Rand0mPa55word!";
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), _random);

            var convertedCertificate =
                new X509Certificate2(stream.ToArray(),
                                        password,
                                        X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            
            // Add the certificate to the certificate store
            X509Store _CertificateStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            _CertificateStore.Open(OpenFlags.ReadWrite);
            _CertificateStore.Add(convertedCertificate);
            _CertificateStore.Close();
        }

        public static T Export<T>(byte[] snkData, Func<RSACryptoServiceProvider, T> processor)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(snkData);

            return processor(rsa);
        }

        public static byte[] ExportPrivateKey(byte[] certificateData, SecureString certificatePassword)
        {
            var privateKey = ExportPrivateKeyToPEM(certificateData, certificatePassword);

            // Certificate does not have a private key.
            if (privateKey.IsNullOrEmpty()) return null;

            var stringBuilder = new StringBuilder();

            foreach (var pemLine in privateKey.Split('\n'))
            {
                // Trim padding CR and white spaces.
                var line = pemLine.TrimEnd('\r').Trim();

                // Skip directives and empty lines.
                if (!(line.Contains("BEGIN RSA PRIVATE KEY") || line.Contains("END RSA PRIVATE KEY") ||
                      line.Length == 0))
                    stringBuilder.Append(line);
            }

            // Decode Base64 to DER.
            return Convert.FromBase64String(stringBuilder.ToString());
        }

        public static string ExportPrivateKeyAsXMLString(byte[] certificateData, SecureString certificatePassword)
        {
            using var x509Certificate2 = new X509Certificate2(
                 certificateData,
                 certificatePassword,
                 X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
             );

            using (var rsa = x509Certificate2.GetRSAPrivateKey())
            {
                return rsa.ToXmlString(true);
            }
        }

        public static string ExportPrivateKeyToPEM(RSACryptoServiceProvider rsaCryptoServiceProvider)
        {
            using (var textWriter = new StringWriter())
            {
                var asymmetricCipherKeyPair = DotNetUtilities.GetRsaKeyPair(rsaCryptoServiceProvider);
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(asymmetricCipherKeyPair.Private);

                return pemWriter.Writer.ToString();
            }
        }

        public static string ExportPrivateKeyToPEM(byte[] certificateData, SecureString certificatePassword)
        {
            using var x509Certificate2 = new X509Certificate2(
                certificateData,
                certificatePassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
            );

            if (!x509Certificate2.HasPrivateKey) return null;

            using (var rsa = x509Certificate2.PrivateKey as RSACryptoServiceProvider)
            {
                return ExportPrivateKeyToPEM(rsa);
            }
        }

        public static byte[] ExportPublicKeyCertificate(byte[] certificateData, SecureString certificatePassword)
        {
            using var x509Certificate2 = new X509Certificate2(certificateData, certificatePassword);

            return x509Certificate2.Export(X509ContentType.Cert);
        }

        public static string ExportPublicKeyCertificateToBase64(byte[] certificateData,
            SecureString certificatePassword)
        {
            return Convert.ToBase64String(ExportPublicKeyCertificate(certificateData, certificatePassword));
        }

        public static string ExportPublicKeyCertificateToPEM(byte[] certificateData)
        {
            using (var textWriter = new StringWriter())
            {
                var x509CertificateParser = new X509CertificateParser();
                var x509Certificate = x509CertificateParser.ReadCertificate(certificateData);
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(x509Certificate);

                return pemWriter.Writer.ToString();
            }
        }

        public static string ExportPublicKeyCertificateToPEM(byte[] certificateData, SecureString certificatePassword)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");

            stringBuilder.AppendLine(
                Convert.ToBase64String(
                    ExportPublicKeyCertificate(certificateData, certificatePassword),
                    Base64FormattingOptions.InsertLineBreaks));

            stringBuilder.AppendLine("-----END CERTIFICATE-----");

            return stringBuilder.ToString();
        }

        public static string ExportPublicKeyToPEM(byte[] certificateData)
        {
            using (var textWriter = new StringWriter())
            {
                var x509CertificateParser = new X509CertificateParser();
                var x509Certificate = x509CertificateParser.ReadCertificate(certificateData);
                var asymmetricKeyParameter = x509Certificate.GetPublicKey();
                var pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(asymmetricKeyParameter);

                return pemWriter.Writer.ToString();
            }
        }

        public static byte[] ExportSnkPrivateKey(byte[] certificateData)
        {
            var privateKey = ExportSnkPrivateKeyToPEM(certificateData);

            // Certificate does not have a private key.
            if (privateKey.IsNullOrEmpty()) return null;

            var stringBuilder = new StringBuilder();

            foreach (var pemLine in privateKey.Split('\n'))
            {
                // Trim padding CR and white spaces.
                var line = pemLine.TrimEnd('\r').Trim();

                // Skip directives and empty lines.
                if (!(line.Contains("BEGIN RSA PRIVATE KEY") || line.Contains("END RSA PRIVATE KEY") ||
                      line.Length == 0))
                    stringBuilder.Append(line);
            }

            // Decode Base64 to DER.
            return Convert.FromBase64String(stringBuilder.ToString());
        }

        public static string ExportSnkPrivateKeyToPEM(byte[] snkCertificateData)
        {
            return Export(snkCertificateData, ExportPrivateKeyToPEM);
        }

        public static byte[] ExportSnkPublicKeyCertificate(byte[] snkCertificateData)
        {
            return Export(
                snkCertificateData,
                rsa =>
                {
                    var destination = new Span<byte>();
                    rsa.TryExportRSAPublicKey(destination, out _);

                    return destination.ToArray();
                });
        }

        public static string ExportSnkPublicKeyCertificateToPEM(byte[] certificateData)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");

            stringBuilder.AppendLine(
                Convert.ToBase64String(
                    ExportSnkPublicKeyCertificate(certificateData),
                    Base64FormattingOptions.InsertLineBreaks));

            stringBuilder.AppendLine("-----END CERTIFICATE-----");

            return stringBuilder.ToString();
        }

        public static byte[] GetPublicKey(byte[] snkData)
        {
            var snkp = new StrongNameKeyPair(snkData);
            var publicKey = snkp.PublicKey;

            return publicKey;
        }

        public static byte[] GetPublicKeyToken(byte[] snkPublicKey)
        {
            using (var csp = new SHA1CryptoServiceProvider())
            {
                var hash = csp.ComputeHash(snkPublicKey);

                var token = new byte[8];

                for (var i = 0; i < 8; i++) token[i] = hash[hash.Length - i - 1];

                return token;
            }
        }
    }
}