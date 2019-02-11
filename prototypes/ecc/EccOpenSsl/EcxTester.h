#pragma once

using namespace System;

namespace EcxOpenSsl {

	class EcxTesterData;

	public ref class EcxTester
	{
		EcxTesterData* m_p;

	public:
		EcxTester();
		~EcxTester();

		void Initialize();
		void Cleanup();

		//void Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
		//void Decode(String^ requestPath, String^ responsePath, array<unsigned char>^% clientSecret, array<unsigned char>^% serverSecret);
		//void SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);

    //My simple tests
    bool VerifyAndSign(
      bool curve448,
      String^ bcCertificateFilePath,
      String^ opensslCertificateFilePath,
      String^ privateKeyFilePath,
      String^ password,
      array<unsigned char>^% dataToSign,
      array<unsigned char>^% bcSignature,
      array<unsigned char>^% opensslSignature);

    bool CalculateAgreement(
      bool X448,
      array<unsigned char>^% bcPublicKey,
      array<unsigned char>^% opensslPublicKey,
      array<unsigned char>^% opensslSecret);
  };
}
