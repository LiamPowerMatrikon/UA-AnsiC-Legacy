#include "stdafx.h"
#include "EccTester.h"

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

// #define EC_CURVE_NAME SN_X9_62_prime256v1
#define EC_CURVE_NAME SN_brainpoolP256r1

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

static String^ FormatHexString(OpcUa_ByteString& bytes, int offset = 0, int length = -1)
{
	if (length < 0)
	{
		length = bytes.Length;
	}

	auto buffer = gcnew System::Text::StringBuilder();

	for (int ii = offset; ii < offset + length; ii++)
	{
		buffer->AppendFormat("{0:X2}", bytes.Data[ii]);
	}

	return buffer->ToString();
}

static void PrintHexString(String^ text, OpcUa_ByteString& bytes, int offset = 0, int length = -1)
{
	Console::WriteLine(text + " {0}", FormatHexString(bytes, offset, length));
}

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

	auto pEcPrivateKey = EVP_PKEY_get1_EC_KEY(pEvpKey);

	if (pEcPrivateKey == nullptr)
	{
		EVP_PKEY_free(pEvpKey);
		return false;
	}

	EVP_PKEY_free(pEvpKey);
	pEvpKey = nullptr;

	pPrivateKey->Length = i2d_ECPrivateKey(pEcPrivateKey, nullptr);
	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	auto pData = pPrivateKey->Data;
	int result = i2d_ECPrivateKey(pEcPrivateKey, &pData);

	if (result != pPrivateKey->Length)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	EC_KEY_free(pEcPrivateKey);

	return true;
}

bool VerifySignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pCertificate)
{
	const unsigned char* pos = pCertificate->Data;

	auto pX509 = d2i_X509((X509**)nullptr, &pos, pCertificate->Length);

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

	auto pEcPublicKey = EVP_PKEY_get1_EC_KEY(pX509PublicKey);

	if (pEcPublicKey == nullptr)
	{
		X509_free(pX509);
		return false;
	}

	X509_free(pX509);
	pX509 = nullptr;

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	OpcUa_ByteString signature;
	signature.Length = keySize*2;
	signature.Data = pData->Data + pData->Length - keySize*2;

	auto pEcSignature = ECDSA_SIG_new();

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto r = BN_bin2bn(signature.Data, keySize, nullptr);

	if (r == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto s = BN_bin2bn(signature.Data + keySize, keySize, nullptr);

	if (s == nullptr)
	{
		BN_free(r);
		EC_KEY_free(pEcPublicKey);
		return false;
	}

  ECDSA_SIG_set0(pEcSignature, r, s);

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length - keySize*2, digest) == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	if (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, pEcSignature, pEcPublicKey) != 1)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPublicKey);

	return true;
}

#define bn2bin_pad(bn,to,len)                           \
    do {                                                \
        int pad_len = (len) - BN_num_bytes(bn);         \
        memset(to, 0, pad_len);                   \
        BN_bn2bin(bn, (to) + pad_len);                  \
    } while(0)

bool CreateSignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSignature)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length, digest) == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

  auto pEcSignature = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, pEcPrivateKey);

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pSignature->Length = keySize * 2;
	pSignature->Data = new unsigned char[pSignature->Length];

	BN_bn2binpad(ECDSA_SIG_get0_r(pEcSignature), pSignature->Data, keySize);
	BN_bn2binpad(ECDSA_SIG_get0_s(pEcSignature), pSignature->Data + keySize, keySize);

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

unsigned int GetSignatureSize(OpcUa_ByteString* pPrivateKey)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return 0;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return 0;
	}

	keySize = (keySize + 7) / 8;
	EC_KEY_free(pEcPrivateKey);

	return keySize * 2;
}

static unsigned int DecodeUInt32(unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < offset + 4)
	{
		return -1;
	}

	unsigned int value = data[offset];

	value += (((unsigned int)data[offset+1]) << 8);
	value += (((unsigned int)data[offset+2]) << 16);
	value += (((unsigned int)data[offset+3]) << 24);

	return value;
}

static void EncodeUInt32(unsigned int value, unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < 4)
	{
		throw gcnew ArgumentException("length");
	}

	data[offset] = (unsigned char)(value & 0x000000FF);
	data[offset + 1] = (unsigned char)((value & 0x0000FF00) >> 8);
	data[offset + 2] = (unsigned char)((value & 0x00FF0000) >> 16);
	data[offset + 3] = (unsigned char)((value & 0xFF000000) >> 24);
}

static OpcUa_ByteString Copy(OpcUa_ByteString& src)
{
	OpcUa_ByteString dst;
	dst.Length = src.Length;
	dst.Data = new unsigned char[dst.Length];
	memcpy(dst.Data, src.Data, dst.Length);
	return dst;
}

static bool Decode(
	unsigned char* data, 
	unsigned int offset, 
	unsigned int length, 
	OpcUa_ByteString* pSenderCertificate, 
	OpcUa_ByteString* pSenderEphemeralKey,
	OpcUa_ByteString* pSenderNonce)
{
	auto totalLength = DecodeUInt32(data, offset, length);
	
	OpcUa_ByteString message;
	message.Data = data + offset;
	message.Length = totalLength;
	offset += 4;

	auto signingCertificateLength = DecodeUInt32(data, offset, length - offset);
	offset += 4;

	auto pSigningCertificateData = data + offset;
	offset += signingCertificateLength;

	OpcUa_ByteString certificate;
	certificate.Length = signingCertificateLength;
	certificate.Data = pSigningCertificateData;

	auto senderKeyLength = DecodeUInt32(data, offset, length - offset);
	offset += 4;

	auto pSenderKeyData = data + offset;
	offset += senderKeyLength;

	OpcUa_ByteString senderKey;
	senderKey.Length = senderKeyLength;
	senderKey.Data = pSenderKeyData;

	auto senderNonceLength = DecodeUInt32(data, offset, length - offset);
	offset += 4;

	auto pSenderNonceData = data + offset;
	offset += senderNonceLength;

	OpcUa_ByteString senderNonce;
	senderNonce.Length = senderNonceLength;
	senderNonce.Data = pSenderNonceData;

	if (!VerifySignature(&message, &certificate))
	{
		return false;
	}

	*pSenderCertificate = Copy(certificate);
	*pSenderEphemeralKey = Copy(senderKey);
	*pSenderNonce = Copy(senderNonce);

	// PrintHexString("CLIENT EKEY", *pSenderEphemeralKey);
	return true;
}

static bool Encode(
	OpcUa_ByteString* pSenderCertificate,
	OpcUa_ByteString* pSenderPrivateKey,
	OpcUa_ByteString* pSenderEphemeralKey,
	OpcUa_ByteString* pSenderNonce,
	OpcUa_ByteString* pMessage)
{
	auto totalLength = 16;
	totalLength += pSenderCertificate->Length;
	totalLength += pSenderEphemeralKey->Length;
	totalLength += pSenderNonce->Length;
	totalLength += GetSignatureSize(pSenderPrivateKey);

	pMessage->Length = totalLength;
	pMessage->Data = new unsigned char[totalLength];

	auto offset = 0;
	EncodeUInt32(totalLength, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	EncodeUInt32(pSenderCertificate->Length, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderCertificate->Data, pSenderCertificate->Length);

	offset += pSenderCertificate->Length;
	EncodeUInt32(pSenderEphemeralKey->Length, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderEphemeralKey->Data, pSenderEphemeralKey->Length);

	offset += pSenderEphemeralKey->Length;
	EncodeUInt32(pSenderNonce->Length, pMessage->Data, offset, pMessage->Length - offset);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderNonce->Data, pSenderNonce->Length);

	offset += pSenderNonce->Length;
	// PrintHexString("SERVER EKEY", *pSenderEphemeralKey);

	OpcUa_ByteString message;
	message.Data = pMessage->Data;
	message.Length = offset;

	OpcUa_ByteString signature;
	signature.Data = nullptr;
	signature.Length = 0;

	if (!CreateSignature(&message, pSenderPrivateKey, &signature))
	{
		delete[] pMessage->Data;
		pMessage->Data = nullptr;
		pMessage->Length = 0;
		return false;
	}

	memcpy(pMessage->Data + offset, signature.Data, signature.Length);
	delete[] signature.Data;

	return true;
}

bool GenerateKeys(
	const char* curveName,
	OpcUa_ByteString* pPublicKey,
	OpcUa_ByteString* pPrivateKey)
{
	pPublicKey->Length = 0;
	pPublicKey->Data = nullptr;

	pPrivateKey->Length = 0;
	pPrivateKey->Data = nullptr;

	int curveId = 0;

	if (strcmp(SN_X9_62_prime256v1, curveName) == 0) { curveId = NID_X9_62_prime256v1; }
	if (strcmp(SN_brainpoolP256r1, curveName) == 0) { curveId = NID_brainpoolP256r1; }

	auto pEcKey = EC_KEY_new_by_curve_name(curveId);

	if (pEcKey == nullptr)
	{
		return false;
	}

	if (EC_KEY_generate_key(pEcKey) == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, NULL);

	if (pPrivateKey->Length == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	if (pPrivateKey->Data == nullptr)
	{
		EC_KEY_free(pEcKey);
		return false; 
	}

	auto pData = pPrivateKey->Data;
	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, &pData);

	if (pPrivateKey->Length == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcKey));

	if (keySize == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pPublicKey->Length = keySize * 2;
	pPublicKey->Data = new unsigned char[pPublicKey->Length];

	if (pPublicKey->Data == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	auto point = EC_KEY_get0_public_key(pEcKey);

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcKey), point, x, y, pCtx))
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		BN_CTX_free(pCtx);
		return false;
	}

	bn2bin_pad(x, pPublicKey->Data, keySize);
	bn2bin_pad(y, pPublicKey->Data + keySize, keySize);

	BN_CTX_free(pCtx);
	EC_KEY_free(pEcKey);
	return true;
}

bool CreateNonce(unsigned int length, OpcUa_ByteString* pNonce)
{
	pNonce->Length = length;
	pNonce->Data = new unsigned char[length];

	if (RAND_bytes(pNonce->Data, length) <= 0)
	{
		delete[] pNonce->Data;
		pNonce->Length = 0;
		pNonce->Data = nullptr;
		return false;
	}

	return true;
}

bool ComputeSecret(
	OpcUa_ByteString* pNonce,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSeed,
	OpcUa_ByteString* pSharedSecret)
{
	const unsigned char* pData = pPrivateKey->Data;
	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pData, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	if (pNonce->Length != 2 * keySize)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	x = BN_bin2bn(pNonce->Data, keySize, x);

	if (x == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	y = BN_bin2bn(pNonce->Data + keySize, keySize, y);

	if (y == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p1 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p1 == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p1, x, y, pCtx))
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p2 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p2 == nullptr)
	{
		EC_POINT_free(p1);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_mul(EC_KEY_get0_group(pEcPrivateKey), p2, NULL, p1, EC_KEY_get0_private_key(pEcPrivateKey), pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p2, x, y, pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pHmacKey = new unsigned char[keySize*2];
	memset(pHmacKey, 0, keySize);
	bn2bin_pad(x, pHmacKey, keySize);

	unsigned int hmacSeedSize = keySize + pSeed->Length;
	auto pHmacSeed = new unsigned char[hmacSeedSize];
	memset(pHmacSeed, 0, hmacSeedSize);
	memcpy(pHmacSeed, pSeed->Data, pSeed->Length);
	memcpy(pHmacSeed + pSeed->Length, pHmacKey, keySize);
	    
	pSharedSecret->Length = SHA256_DIGEST_LENGTH;
	pSharedSecret->Data = new unsigned char[SHA256_DIGEST_LENGTH];

	if (::HMAC(EVP_sha256(), pHmacKey, keySize, pHmacSeed, hmacSeedSize, pSharedSecret->Data, nullptr) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pHmacKey;
		delete[] pHmacSeed;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	/*
	if (::SHA256(pBuffer, keySize, pSharedSecret->Data) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pBuffer;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}
	*/

	delete[] pHmacKey;
	delete[] pHmacSeed;
	EC_POINT_free(p1);
	EC_POINT_free(p2);
	BN_CTX_free(pCtx);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

static bool DeriveKeys(OpcUa_ByteString* pSecret, OpcUa_ByteString* pSeed, unsigned int length, OpcUa_ByteString* pKeys)
{
	//PrintHexString("SSL: SECRET: ", *pSecret);
	//PrintHexString("SSL: SEED: ", *pSeed);

	unsigned int hashLength = SHA256_DIGEST_LENGTH;
	auto hash = new unsigned char[hashLength];

	if (::HMAC(EVP_sha256(), pSecret->Data, pSecret->Length, pSeed->Data, pSeed->Length, hash, nullptr) == nullptr)
	{
		delete[] hash;
		return false;
	}

	//OpcUa_ByteString x;
	//x.Data = hash;
	//x.Length = hashLength;
	//PrintHexString("SSL: A(1): ", x);

	auto dataLength = SHA256_DIGEST_LENGTH + pSeed->Length;
	auto data = new unsigned char[dataLength];
	memcpy(data, hash, hashLength);
	memcpy(data + hashLength, pSeed->Data, pSeed->Length);

	//x.Data = data;
	//x.Length = dataLength;
	//PrintHexString("SSL: S(1): ", x);

	// create buffer with requested size.
	auto output = new unsigned char[length];

	unsigned int position = 0;

	do
	{
		if (::HMAC(EVP_sha256(), pSecret->Data, pSecret->Length, data, dataLength, hash, nullptr) == nullptr)
		{
			delete[] hash;
			delete[] data;
			return false;
		}

		//x.Data = hash;
		//x.Length = hashLength;
		//PrintHexString("SSL: R(1): ", x);

		for (unsigned int ii = 0; position < length && ii < hashLength; ii++)
		{
			output[position++] = hash[ii];
		}

		if (::HMAC(EVP_sha256(), pSecret->Data, pSecret->Length, data, hashLength, hash, nullptr) == nullptr)
		{
			delete[] hash;
			delete[] data;
			return false;
		}

		memcpy(data, hash, hashLength);
	} 
	while (position < length);

	delete[] hash;

	pKeys->Data = output;
	pKeys->Length = length;

	return true;
}

static bool AreEqual(OpcUa_ByteString& value1, OpcUa_ByteString& value2)
{
	if (value2.Length != value1.Length)
	{
		return false;
	}

	for (auto ii = 0U; ii < value1.Length; ii++)
	{
		if (value1.Data[ii] != value2.Data[ii])
		{
			return false;
		}
	}

	return true;
}

namespace EccOpenSsl {

	class EccTesterData
	{
	public:

		EccTesterData()
		{
			memset(&Certificate, 0, sizeof(OpcUa_ByteString));
			memset(&PrivateKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPublicKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPrivateKey, 0, sizeof(OpcUa_ByteString));
		}

		~EccTesterData()
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

	EccTester::EccTester()
	{
		m_p = new EccTesterData();
	}

	EccTester::~EccTester()
	{
		delete m_p;
	}

	void EccTester::SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		if (!LoadCertificate(pFilePath, &m_p->Certificate))
		{
			throw gcnew ArgumentException("certificateFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &m_p->PrivateKey))
		{
			throw gcnew ArgumentException("privateKeyFilePath");
		}
	}

	void EccTester::Decode(String^ requestPath, String^ responsePath, array<unsigned char>^% clientSecret, array<unsigned char>^% serverSecret)
	{
		auto bytes = File::ReadAllBytes(requestPath);

		auto message = new unsigned char[bytes->Length];

		OpcUa_ByteString clientCertificate = { 0, 0 };
		OpcUa_ByteString clientEphemeralPublicKey = { 0, 0 };
		OpcUa_ByteString clientNonce = { 0, 0 };
		OpcUa_ByteString response = { 0, 0 };
		OpcUa_ByteString localClientSecret = { 0, 0 };
		OpcUa_ByteString localServerSecret = { 0, 0 };
		OpcUa_ByteString serverNonce = { 0, 0 };
		OpcUa_ByteString derivedKeys = { 0, 0 };

		try
		{
			Marshal::Copy(bytes, 0, (IntPtr)message, bytes->Length);

			if (!::Decode(message, 0, bytes->Length, &clientCertificate, &clientEphemeralPublicKey, &clientNonce))
			{
				throw gcnew ArgumentException("messagePath");
			}

			if (!GenerateKeys(EC_CURVE_NAME, &m_p->EphemeralPublicKey, &m_p->EphemeralPrivateKey))
			{
				throw gcnew ArgumentException("generateKeys");
			}

			if (!CreateNonce(m_p->EphemeralPublicKey.Length / 2, &serverNonce))
			{
				throw gcnew ArgumentException("createNonce");
			}


			OpcUa_ByteString nonce;
			static const char* client = "client";
			nonce.Data = (unsigned char*)client;
			nonce.Length = 6;
			PrintHexString("SSL: ClientNonce: ", nonce);

			if (!ComputeSecret(&clientEphemeralPublicKey, &m_p->EphemeralPrivateKey, &nonce, &localClientSecret))
			{
				throw gcnew ArgumentException("computeSecret");
			}

			PrintHexString("SSL: ClientSecret: ", localClientSecret);

			static const char* server = "server";
			nonce.Data = (unsigned char*)server;
			nonce.Length = 6;
			PrintHexString("SSL: ServerNonce: ", nonce);

			if (!ComputeSecret(&clientEphemeralPublicKey, &m_p->EphemeralPrivateKey, &nonce, &localServerSecret))
			{
				throw gcnew ArgumentException("computeSecret");
			}

			PrintHexString("SSL: ServerSecret: ", localServerSecret);

			if (!DeriveKeys(&localServerSecret, &localClientSecret, 80, &derivedKeys))
			{
				throw gcnew ArgumentException("deriveKeys");
			}

			Console::WriteLine("==== SSL Derived Keys ====");
			PrintHexString("SSL: ServerSigningKey: ", derivedKeys, 0, 32);
			PrintHexString("SSL: ServerEncryptingKey: ", derivedKeys, 32, 32);
			PrintHexString("SSL: ServerInitializationVector: ", derivedKeys, 64, 16);

			delete [] derivedKeys.Data;

			if (!DeriveKeys(&localClientSecret, &localServerSecret, 80, &derivedKeys))
			{
				throw gcnew ArgumentException("deriveKeys");
			}

			PrintHexString("SSL: ClientSigningKey: ", derivedKeys, 0, 32);
			PrintHexString("SSL: ClientEncryptingKey: ", derivedKeys, 32, 32);
			PrintHexString("SSL: ClientInitializationVector: ", derivedKeys, 64, 16);
			
			if (!::Encode(&m_p->Certificate, &m_p->PrivateKey, &m_p->EphemeralPublicKey, &serverNonce, &response))
			{
				throw gcnew ArgumentException("encode");
			}

			bytes = gcnew array<unsigned char>(response.Length);
			Marshal::Copy((IntPtr)response.Data, bytes, 0, bytes->Length);
			File::WriteAllBytes(responsePath, bytes);

			clientSecret = gcnew array<unsigned char>(localClientSecret.Length);
			Marshal::Copy((IntPtr)localClientSecret.Data, clientSecret, 0, clientSecret->Length);

			serverSecret = gcnew array<unsigned char>(localServerSecret.Length);
			Marshal::Copy((IntPtr)localServerSecret.Data, serverSecret, 0, serverSecret->Length);
		}
		finally
		{
			delete[] message;
			delete[] clientCertificate.Data;
			delete[] clientEphemeralPublicKey.Data;
			delete[] clientNonce.Data;
			delete[] localClientSecret.Data;
			delete[] localServerSecret.Data;
			delete[] serverNonce.Data;
		}
	}

	void EccTester::Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		OpcUa_ByteString certificate;
		OpcUa_ByteString privateKey;

		if (!LoadCertificate(pFilePath, &certificate))
		{
			throw gcnew ArgumentException("keyFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &privateKey))
		{
			throw gcnew ArgumentException("keyFilePath");
		}
	}

	void EccTester::Initialize()
	{
		OpenSSL_add_all_algorithms();
		RAND_screen();
		SSL_library_init();
		SSL_load_error_strings();
	}

	void EccTester::Cleanup()
	{
		SSL_COMP_free_compression_methods();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
	}
}