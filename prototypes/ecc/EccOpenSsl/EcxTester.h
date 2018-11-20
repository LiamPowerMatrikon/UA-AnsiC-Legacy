#pragma once

using namespace System;

namespace EccOpenSsl {

	class EcxTesterData;

	public ref class EcxTester
	{
		EcxTesterData* m_p;

	public:
		EcxTester();
		~EcxTester();

		void Initialize();
		void Cleanup();

		void Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
		void Decode(String^ requestPath, String^ responsePath, array<unsigned char>^% clientSecret, array<unsigned char>^% serverSecret);
		void SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password);
	};
}
