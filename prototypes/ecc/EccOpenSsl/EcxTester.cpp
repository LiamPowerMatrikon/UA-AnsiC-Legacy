#include "stdafx.h"
#include "EcxTester.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <memory.h>

using namespace msclr::interop;
using namespace System::IO;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::Runtime::InteropServices;

struct _OpcUa_ByteString
{
	unsigned int Length;
	unsigned char* Data;
};

typedef struct _OpcUa_ByteString OpcUa_ByteString;

struct _OpcUa_Key
{
	unsigned int Type;
	OpcUa_ByteString Key;
};

typedef struct _OpcUa_Key OpcUa_Key;

bool LoadCertificate(const char* filePath, OpcUa_ByteString* pCertificate)
{
  pCertificate->Length = 0;
  pCertificate->Data = nullptr;

  auto pFile = BIO_new_file(filePath, "rb");

  if (pFile == nullptr)
  {
    return false;
  }

  auto pX509 = d2i_X509_bio(pFile, (X509**)nullptr);

  if (pX509 == nullptr)
  {
    BIO_free(pFile);
    return false;
  }

  BIO_free(pFile);
  pFile = nullptr;

  pCertificate->Length = i2d_X509(pX509, NULL);
  auto pBuffer = pCertificate->Data = new unsigned char[pCertificate->Length];
  auto pos = pBuffer;

  auto result = i2d_X509(pX509, &pos);

  if (result != pCertificate->Length)
  {
    X509_free(pX509);
    return false;
  }

  X509_free(pX509);
  pX509 = nullptr;

  return true;
}

bool LoadPrivateKey(const char* filePath, const char* password, OpcUa_ByteString* pPrivateKey)
{
  pPrivateKey->Length = 0;
  pPrivateKey->Data = nullptr;

  auto pFile = BIO_new_file(filePath, "rb");

  if (pFile == nullptr)
  {
    return false;
  }

  auto pEvpKey = PEM_read_bio_PrivateKey(pFile, NULL, 0, (void*)password);

  if (pEvpKey == nullptr)
  {
    BIO_free(pFile);
    return false;
  }

  BIO_free(pFile);
  pFile = nullptr;

  pPrivateKey->Length = i2d_PrivateKey(pEvpKey, nullptr);
  pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

  auto pData = pPrivateKey->Data;
  int result = i2d_PrivateKey(pEvpKey, &pData);

  if (result != pPrivateKey->Length)
  {
    EVP_PKEY_free(pEvpKey);
    return false;
  }

  EVP_PKEY_free(pEvpKey);

  return true;
}

static bool VerifyAndSign_(
  bool curve448,
  OpcUa_ByteString* bcCertificateDer,
  OpcUa_ByteString* opensslCertificateDer,
  OpcUa_ByteString* privateKeyDer,
  OpcUa_ByteString* dataToSign,
  OpcUa_ByteString* bcSignature,
  OpcUa_ByteString* opensslSignature)
{
  const unsigned char* pos = bcCertificateDer->Data;

  auto pX509 = d2i_X509((X509**)nullptr, &pos, bcCertificateDer->Length);

  if (pX509 == nullptr)
  {
    return false;
  }

  auto pX509PublicKey = X509_get_pubkey(pX509);

  if (pX509PublicKey == nullptr)
  {
    X509_free(pX509);
    return false;
  }

  EVP_MD_CTX*      ctx;
  EVP_PKEY_CTX*    pctx;
  int        ret;

  ctx = EVP_MD_CTX_new();

  int id = EVP_PKEY_ED25519;
  if (curve448)
  {
    id = EVP_PKEY_ED448;
  }

  pctx = EVP_PKEY_CTX_new_id(id, NULL);

  ret = EVP_DigestVerifyInit(ctx, &pctx, NULL, NULL, pX509PublicKey);
  if (ret < 1)
  {
    return false;
  }

  ret = EVP_DigestVerify(ctx, (const unsigned char*)bcSignature->Data, (size_t)bcSignature->Length, (const unsigned char*)dataToSign->Data, (size_t)(dataToSign->Length));
  if (ret < 1)
  {
    return false;
  }

  {
    const unsigned char* pos = privateKeyDer->Data;

    auto pEcxPrivateKey = d2i_PrivateKey(id, NULL, &pos, privateKeyDer->Length);

    if (pEcxPrivateKey == nullptr)
    {
      return false;
    }

    EVP_MD_CTX*      ctx;
    EVP_PKEY_CTX*    pctx;
    int ret;

    ctx = EVP_MD_CTX_new();
    pctx = EVP_PKEY_CTX_new_id(id, NULL);

    ret = EVP_DigestSignInit(ctx, &pctx, NULL, NULL, pEcxPrivateKey);
    if (ret < 1)
    {
      return false;
    }

    opensslSignature->Length = 64;
    if (curve448)
    {
      opensslSignature->Length = 114;
    }

    opensslSignature->Data = new unsigned char[opensslSignature->Length];
    
    ret = EVP_DigestSign(ctx, (unsigned char*)opensslSignature->Data, (unsigned int*)&(opensslSignature->Length), (const unsigned char*)dataToSign->Data, (int)dataToSign->Length);
    if (ret < 1)
    {
      return false;
    }
  }

  return true;
}

static bool CalculateAgreement_(
  bool X448,
  OpcUa_ByteString* bcPublicKey,
  OpcUa_ByteString* opensslPublicKey,
  OpcUa_ByteString* opensslSecret)
{
  int id = EVP_PKEY_X25519;
  if (X448)
  {
    id = EVP_PKEY_X448;
  }

  size_t keylen = 0;
  int ret = 0;
  EVP_PKEY* pEvpKey = NULL;
  {
    //Create keys
    EVP_PKEY_CTX* pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(id, NULL);
    ret = EVP_PKEY_keygen_init(pctx);
    if (ret < 1)
    {
      return false;
    }

    ret = EVP_PKEY_keygen(pctx, &pEvpKey);
    if (ret < 1)
    {
      return false;
    }

    EVP_PKEY_CTX_free(pctx);

    ret = EVP_PKEY_get_raw_public_key(pEvpKey, 0, &opensslPublicKey->Length);
    if (ret < 1)
    {
      return false;
    }

    opensslPublicKey->Data = new uint8_t[opensslPublicKey->Length];

    ret = EVP_PKEY_get_raw_public_key(pEvpKey, opensslPublicKey->Data, &opensslPublicKey->Length);
    if (ret < 1)
    {
      return false;
    }

  }

  EVP_PKEY* pEcRemotePublicKey = EVP_PKEY_new_raw_public_key(id, 0, bcPublicKey->Data, bcPublicKey->Length);
  if (pEcRemotePublicKey == nullptr)
  {
    return false;
  }

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pEvpKey, NULL);
  ret = EVP_PKEY_derive_init(pctx);
  if (ret < 1)
  {
    return false;
  }
  ret = EVP_PKEY_derive_set_peer(pctx, pEcRemotePublicKey);
  if (ret < 1)
  {
    return false;
  }

  ret = EVP_PKEY_derive(pctx, NULL, &keylen);
  if (ret < 1)
  {
    return false;
  }

  opensslSecret->Data = new uint8_t[keylen];
  opensslSecret->Length = keylen;

  ret = EVP_PKEY_derive(pctx, opensslSecret->Data, &opensslSecret->Length);
  if (ret < 1)
  {
    return false;
  }

  return true;
}

namespace EcxOpenSsl {

	class EcxTesterData
	{
	public:

    EcxTesterData()
		{
			memset(&Certificate, 0, sizeof(OpcUa_ByteString));
			memset(&PrivateKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPublicKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPrivateKey, 0, sizeof(OpcUa_ByteString));
		}

		~EcxTesterData()
		{
			if (Certificate.Data != nullptr)
			{
				delete[] Certificate.Data;
			}

			if (PrivateKey.Data != nullptr)
			{
				delete[] PrivateKey.Data;
			}

			if (EphemeralPublicKey.Data != nullptr)
			{
				delete[] EphemeralPublicKey.Data;
			}

			if (EphemeralPrivateKey.Data != nullptr)
			{
				delete[] EphemeralPrivateKey.Data;
			}
		}

		OpcUa_ByteString Certificate;
		OpcUa_ByteString PrivateKey;
		OpcUa_ByteString EphemeralPublicKey;
		OpcUa_ByteString EphemeralPrivateKey;
	};

	EcxTester::EcxTester()
	{
		m_p = new EcxTesterData();
	}

  EcxTester::~EcxTester()
	{
		delete m_p;
	}

  bool EcxTester::VerifyAndSign(
    bool curve448,
    String^ bcCertificateFilePath,
    String^ opensslCertificateFilePath,
    String^ privateKeyFilePath,
    String^ password,
    array<unsigned char>^% dataToSign,
    array<unsigned char>^% bcSignature,
    array<unsigned char>^% opensslSignature)
  {
    bool result = false;

    OpcUa_ByteString bcCertificateDer = { 0, 0 };
    OpcUa_ByteString opensslCertificateDer = { 0, 0 };
    OpcUa_ByteString privateKeyDer = { 0, 0 };
    OpcUa_ByteString dataToSign_ = { 0, 0 };
    OpcUa_ByteString bcSignature_ = { 0, 0 };
    OpcUa_ByteString opensslSignature_ = { 0, 0 };

    try
    {
      {
        marshal_context context;
        auto pFilePath = context.marshal_as<const char*>(bcCertificateFilePath);

        if (!LoadCertificate(pFilePath, &bcCertificateDer))
        {
          throw gcnew ArgumentException("bcCertificateFilePath");
        }
      }

      {
        marshal_context context;
        auto pFilePath = context.marshal_as<const char*>(opensslCertificateFilePath);

        if (!LoadCertificate(pFilePath, &opensslCertificateDer))
        {
          throw gcnew ArgumentException("opensslCertificateFilePath");
        }
      }

      {
        marshal_context context;
        auto pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
        auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

        if (!LoadPrivateKey(pFilePath, pPassword, &privateKeyDer))
        {
          throw gcnew ArgumentException("privateKeyFilePath");
        }
      }

      dataToSign_.Length = dataToSign->Length;
      dataToSign_.Data = new unsigned char[dataToSign->Length];
      Marshal::Copy(dataToSign, 0, (IntPtr)dataToSign_.Data, dataToSign->Length);

      bcSignature_.Length = bcSignature->Length;
      bcSignature_.Data = new unsigned char[bcSignature->Length];
      Marshal::Copy(bcSignature, 0, (IntPtr)bcSignature_.Data, bcSignature->Length);

      result = VerifyAndSign_(
        curve448,
        &bcCertificateDer,
        &opensslCertificateDer,
        &privateKeyDer,
        &dataToSign_,
        &bcSignature_,
        &opensslSignature_);

      opensslSignature = gcnew array<unsigned char>(opensslSignature_.Length);
      Marshal::Copy((IntPtr)opensslSignature_.Data, opensslSignature, 0, opensslSignature->Length);

    }
    finally
    {
      delete[] bcCertificateDer.Data;
      delete[] opensslCertificateDer.Data;
      delete[] privateKeyDer.Data;
      delete[] dataToSign_.Data;
      delete[] bcSignature_.Data;
      delete[] opensslSignature_.Data;
    }
      
    return result;
  }

  bool EcxTester::CalculateAgreement(
    bool X448,
    array<unsigned char>^% bcPublicKey,
    array<unsigned char>^% opensslPublicKey,
    array<unsigned char>^% opensslSecret)
  {
    bool result = false;

    OpcUa_ByteString bcPublicKey_ = { 0, 0 };
    OpcUa_ByteString opensslPrivateKey_ = { 0, 0 };
    OpcUa_ByteString opensslPublicKey_ = { 0, 0 };
    OpcUa_ByteString opensslSecret_ = { 0, 0 };

    try
    {
      bcPublicKey_.Length = bcPublicKey->Length;
      bcPublicKey_.Data = new unsigned char[bcPublicKey->Length];
      Marshal::Copy(bcPublicKey, 0, (IntPtr)bcPublicKey_.Data, bcPublicKey_.Length);

      result = CalculateAgreement_(
        X448,
        &bcPublicKey_,
        &opensslPublicKey_,
        &opensslSecret_);

      opensslPublicKey = gcnew array<unsigned char>(opensslPublicKey_.Length);
      Marshal::Copy((IntPtr)opensslPublicKey_.Data, opensslPublicKey, 0, opensslPublicKey->Length);

      opensslSecret = gcnew array<unsigned char>(opensslSecret_.Length);
      Marshal::Copy((IntPtr)opensslSecret_.Data, opensslSecret, 0, opensslSecret->Length);

    }
    finally
    {
      delete[] bcPublicKey_.Data;
      delete[] opensslPrivateKey_.Data;
      delete[] opensslPublicKey_.Data;
      delete[] opensslSecret_.Data;
    }

    return result;
  }

	void EcxTester::Initialize()
	{
		OpenSSL_add_all_algorithms();
		RAND_screen();
		SSL_library_init();
		SSL_load_error_strings();
	}

	void EcxTester::Cleanup()
	{
		SSL_COMP_free_compression_methods();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
	}
}