#define CURVE25519
//#define CURVE448

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Numerics;
using Opc.Ua;

using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;

namespace EcxTestClient
{
    class Program
    {

        static void Main(string[] args)
        {
            EdSignAndVerify();

            XDiffieHellman();

        }

        static ISigner CreateSigner(Ed25519.Algorithm algorithm, byte[] context)
        {
            switch (algorithm)
            {
                case Ed25519.Algorithm.Ed25519:
                    return new Ed25519Signer();
                case Ed25519.Algorithm.Ed25519ctx:
                    return new Ed25519ctxSigner(context);
                case Ed25519.Algorithm.Ed25519ph:
                    return new Ed25519phSigner(context);
                default:
                    throw new ArgumentException("algorithm");
            }
        }
        static ISigner CreateSigner(Ed448.Algorithm algorithm, byte[] context)
        {
            switch (algorithm)
            {
                case Ed448.Algorithm.Ed448:
                    byte[] emptyContext = new byte[0];
                    return new Ed448Signer(emptyContext);
                case Ed448.Algorithm.Ed448ph:
                    return new Ed448phSigner(context);
                default:
                    throw new ArgumentException("algorithm");
            }
        }


        static byte[] RandomContext(int length, SecureRandom random)
        {
            byte[] context = new byte[length];
            random.NextBytes(context);
            return context;
        }

        static void EdSignAndVerify()
        {
#if CURVE25519
            string bcCertName = "liam";
            string opensslCertName = "louise";
#endif
#if CURVE448
            string bcCertName = "jim";
            string opensslCertName = "joan";
#endif
            // certs are generated with OpenSSL
            string bcCertificateFilePath = Path.Combine("..\\..\\..\\..\\pki\\certs\\", bcCertName + ".der");
            string bcKeyFilePath = Path.Combine("..\\..\\..\\..\\pki\\private\\", bcCertName + ".pem");

            string opensslCertificateFilePath = Path.Combine("..\\..\\..\\..\\pki\\certs\\", opensslCertName + ".der");
            string opensslKeyFilePath = Path.Combine("..\\..\\..\\..\\pki\\private\\", opensslCertName + ".pem");

            //Load my certificate and private key
            byte[] bcCertificateBytes = System.IO.File.ReadAllBytes(bcCertificateFilePath);
            X509Certificate bcCertificate = new X509CertificateParser().ReadCertificate(bcCertificateBytes);

            ICipherParameters bcPrivateKey;
#if CURVE25519
            using (var reader = File.OpenText(bcKeyFilePath))
                bcPrivateKey = (Ed25519PrivateKeyParameters)new PemReader(reader).ReadObject();
#endif
#if CURVE448
            using (var reader = File.OpenText(bcKeyFilePath))
                bcPrivateKey = (Ed448PrivateKeyParameters)new PemReader(reader).ReadObject();
#endif
            //Create random data for signing
            SecureRandom random = new SecureRandom();
            byte[] dataToSign = new byte[random.NextInt() & 255];
            random.NextBytes(dataToSign);

            //Sign data
            byte[] context = RandomContext(random.NextInt() & 255, random);
#if CURVE25519
            ISigner signer = CreateSigner(Ed25519.Algorithm.Ed25519, context);
#endif
#if CURVE448
            ISigner signer = CreateSigner(Ed448.Algorithm.Ed448, context);
#endif
            signer.Init(true, bcPrivateKey);
            signer.BlockUpdate(dataToSign, 0, dataToSign.Length);
            byte[] bcSignature = signer.GenerateSignature();

            {
                //Local verify to validate key pair
#if CURVE25519
                ICipherParameters bcPublicKey = (Ed25519PublicKeyParameters)bcCertificate.GetPublicKey();
                ISigner verifier_ = CreateSigner(Ed25519.Algorithm.Ed25519, context);
#endif
#if CURVE448
                ICipherParameters bcPublicKey = (Ed448PublicKeyParameters)bcCertificate.GetPublicKey();
                ISigner verifier_ = CreateSigner(Ed448.Algorithm.Ed448, context);
#endif

                verifier_.Init(false, bcPublicKey);
                verifier_.BlockUpdate(dataToSign, 0, dataToSign.Length);
                if (!verifier_.VerifySignature(bcSignature))
                {
                    throw new Exception("Local verify failed");
                }
            }

            //Call tester
            byte[] opensslSignature = new byte[0];

            {
                EcxOpenSsl.EcxTester tester = new EcxOpenSsl.EcxTester();
                tester.Initialize();

                bool curve448 = false;
#if CURVE448
                curve448 = true;
#endif

                if (!tester.VerifyAndSign(
                    curve448,
                    bcCertificateFilePath,
                    opensslCertificateFilePath,
                    opensslKeyFilePath,
                    "password",
                    ref dataToSign,
                    ref bcSignature,
                    ref opensslSignature))
                {
                    throw new Exception("Remote verify and sign failed");
                }

                tester.Cleanup();
            }

            //Verify tester signature
            byte[] opensslCertificateBytes = System.IO.File.ReadAllBytes(opensslCertificateFilePath);
            X509Certificate opensslCertificate = new X509CertificateParser().ReadCertificate(opensslCertificateBytes);
#if CURVE25519
            ICipherParameters opensslPublicKey = (Ed25519PublicKeyParameters)opensslCertificate.GetPublicKey();
            ISigner verifier = CreateSigner(Ed25519.Algorithm.Ed25519, context);
#endif
#if CURVE448
            ICipherParameters opensslPublicKey = (Ed448PublicKeyParameters)opensslCertificate.GetPublicKey();
            ISigner verifier = CreateSigner(Ed448.Algorithm.Ed448, context);
#endif

            verifier.Init(false, opensslPublicKey);
            verifier.BlockUpdate(dataToSign, 0, dataToSign.Length);
            if (!verifier.VerifySignature(opensslSignature))
            {
                throw new Exception("Remote verify failed");
            }
        }

        static void XDiffieHellman()
        {
            SecureRandom random = new SecureRandom();

#if CURVE25519
            IAsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();
            kpGen.Init(new X25519KeyGenerationParameters(random));

            AsymmetricCipherKeyPair bcKeyPair = kpGen.GenerateKeyPair();
            byte[] bcPublicKey = new byte[X25519PublicKeyParameters.KeySize];

            ((X25519PublicKeyParameters)(bcKeyPair.Public)).Encode(bcPublicKey, 0);
            X25519Agreement agree = new X25519Agreement();
#endif
#if CURVE448
            IAsymmetricCipherKeyPairGenerator kpGen = new X448KeyPairGenerator();
            kpGen.Init(new X448KeyGenerationParameters(random));

            AsymmetricCipherKeyPair bcKeyPair = kpGen.GenerateKeyPair();
            byte[] bcPublicKey = new byte[X448PublicKeyParameters.KeySize];

            ((X448PublicKeyParameters)(bcKeyPair.Public)).Encode(bcPublicKey, 0);
            X448Agreement agree = new X448Agreement();
#endif

            //Call tester
            byte[] opensslPubKeyBytes = new byte[0];
            byte[] opensslSecret = new byte[0];

            {
                EcxOpenSsl.EcxTester tester = new EcxOpenSsl.EcxTester();
                tester.Initialize();

                bool curve448 = false;
#if CURVE448
                curve448 = true;
#endif

                if (!tester.CalculateAgreement(
                    curve448,
                    ref bcPublicKey,
                    ref opensslPubKeyBytes,
                    ref opensslSecret))
                {
                    throw new Exception("CalculateAgreement failed");
                }

                tester.Cleanup();
            }

#if CURVE25519
            X25519PublicKeyParameters opensslPubKey = new X25519PublicKeyParameters(opensslPubKeyBytes, 0);
#endif
#if CURVE448
            X448PublicKeyParameters opensslPubKey = new X448PublicKeyParameters(opensslPubKeyBytes, 0);
#endif

            agree.Init(bcKeyPair.Private);
            byte[] secret = new byte[agree.AgreementSize];
            agree.CalculateAgreement(opensslPubKey, secret, 0);
            
            if (!Enumerable.SequenceEqual(secret, opensslSecret))
            {
                throw new Exception("Verify failed");
            }

        }

    }
}
