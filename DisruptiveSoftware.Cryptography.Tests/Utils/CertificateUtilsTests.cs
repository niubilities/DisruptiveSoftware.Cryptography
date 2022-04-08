using DisruptiveSoftware.Cryptography.Utils;
using NUnit.Framework;
using Shouldly;
using System;

namespace DisruptiveSoftware.Cryptography.Tests.Utils
{
    using System.IO;
    using System.Reflection;
    using System.Security;
    using System.Security.Cryptography;
    using NUnit.Framework.Internal;

    [TestFixture]
    public class CertificateUtilsTests
    {
        [SetUp]
        public void Setup()
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="file">e.x.  @"Files\test.pdf"</param>
        /// <returns></returns>
        public static string GetFilePath(string file)
        {
            return Path.Combine(TestContext.CurrentContext.TestDirectory, file);
        }

        public static byte[] GetResource(string resouceFullPathName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(resouceFullPathName);

            if (stream != null)
            {
                using var reader = new BinaryReader(stream);

                Span<byte> buffer = new Span<byte>();
                var count = reader.Read(buffer);
                return buffer.ToArray();
            }
            return null;
        }
        public static byte[] GetResourceFromTestData(string resouceName)
        {
            return GetResource($"DisruptiveSoftware.Cryptography.Tests.TestData.{resouceName}");
        }
        [Test]
        public void Export_StateUnderTest_ExpectedBehavior()
        {
            // Arrange 
            byte[] snkData = null;
            Func processor = null;

            // Act
            var result = CertificateUtils.Export(
                snkData,
                processor);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPrivateKey_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPrivateKey(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPrivateKeyAsXMLString_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPrivateKeyAsXMLString(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPrivateKeyToPEM_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            RSACryptoServiceProvider rsaCryptoServiceProvider = null;

            // Act
            var result = CertificateUtils.ExportPrivateKeyToPEM(
                rsaCryptoServiceProvider);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPrivateKeyToPEM_StateUnderTest_ExpectedBehavior1()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPrivateKeyToPEM(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPublicKeyCertificate_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPublicKeyCertificate(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPublicKeyCertificateToBase64_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPublicKeyCertificateToBase64(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPublicKeyCertificateToPEM_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;

            // Act
            var result = CertificateUtils.ExportPublicKeyCertificateToPEM(
                certificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPublicKeyCertificateToPEM_StateUnderTest_ExpectedBehavior1()
        {
            // Arrange

            byte[] certificateData = null;
            SecureString certificatePassword = null;

            // Act
            var result = CertificateUtils.ExportPublicKeyCertificateToPEM(
                certificateData,
                certificatePassword);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportPublicKeyToPEM_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;

            // Act
            var result = CertificateUtils.ExportPublicKeyToPEM(
                certificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportSnkPrivateKey_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;

            // Act
            var result = CertificateUtils.ExportSnkPrivateKey(
                certificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportSnkPrivateKeyToPEM_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] snkCertificateData = null;

            // Act
            var result = CertificateUtils.ExportSnkPrivateKeyToPEM(
                snkCertificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportSnkPublicKeyCertificate_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] snkCertificateData = null;

            // Act
            var result = CertificateUtils.ExportSnkPublicKeyCertificate(
                snkCertificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void ExportSnkPublicKeyCertificateToPEM_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] certificateData = null;

            // Act
            var result = CertificateUtils.ExportSnkPublicKeyCertificateToPEM(
                certificateData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void GetPublicKey_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] snkData = null;

            // Act
            var result = CertificateUtils.GetPublicKey(
                snkData);

            // Assert
            Assert.Fail();
        }

        [Test]
        public void GetPublicKeyToken_StateUnderTest_ExpectedBehavior()
        {
            // Arrange

            byte[] snkPublicKey = null;

            // Act
            var result = CertificateUtils.GetPublicKeyToken(
                snkPublicKey);

            // Assert
            Assert.Fail();
        }
    }
}
