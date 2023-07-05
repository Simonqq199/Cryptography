#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;

#include "pssr.h"
using CryptoPP::PSS;

#include "sha.h"
using CryptoPP::SHA1;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

void pause()
{
#ifdef __linux__
    wcout << "Pausing. Press any key to resume ...";
    wcin.get();
    wcout << endl;
#elif _WIN32
    system("pause");
#else
#endif
}

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        // Message
        string message = "RSA Encryption Schemes";

        // Signer object
        RSASS<PSS, SHA1>::Signer signer(privateKey);

        // Create signature space
        size_t length = signer.MaxSignatureLength();
        SecByteBlock signature(length);

        // Sign message
        signer.SignMessage(rng, (const CryptoPP::byte*)message.c_str(),
            message.length(), signature);

        // Verifier object
        RSASS<PSS, SHA1>::Verifier verifier(publicKey);

        // Verify
        bool result = verifier.VerifyMessage((const CryptoPP::byte*)message.c_str(),
            message.length(), signature, signature.size());

        // Result
        if (true == result) {
            cout << "Signature on message verified" << endl;
            cout << message << "\n";
        }
        else {
            cout << "Message verification failed" << endl;
        }

    } // try

    catch (CryptoPP::Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    pause();

    return 0;
}

void SaveKey(const RSA::PublicKey& PublicKey, const string& filename)
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref()
    );
}

void SaveKey(const RSA::PrivateKey& PrivateKey, const string& filename)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref()
    );
}

void LoadKey(const string& filename, RSA::PublicKey& PublicKey)
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
    );
}

void LoadKey(const string& filename, RSA::PrivateKey& PrivateKey)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
    );
}