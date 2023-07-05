#include <iostream>
#include <string>
#include <cstring>
#include <exception>
#include <assert.h>
#include "cryptlib.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"
#include "files.h"

using namespace std;
using namespace CryptoPP;

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
    // Generate keys
    AutoSeededRandomPool rng;

    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1024);

    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    // Secret to protect
    string plaintext = "RSA Encryption Schemes";

    // Encrypt
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    size_t ecl = encryptor.CiphertextLength(plaintext.size());
    SecByteBlock ciphertext(ecl);

    encryptor.Encrypt(rng, (byte const*)plaintext.data(), plaintext.size(), ciphertext);

    // Decrypt
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
    SecByteBlock recovered(dpl);

    DecodingResult result = decryptor.Decrypt(rng, ciphertext, ciphertext.size(), recovered);

    assert(result.isValidCoding);

    recovered.resize(result.messageLength);

    // Verify
    string ciphertextStr((char*)ciphertext.data(), ciphertext.size());
    string recoveredStr((char*)recovered.data(), recovered.size());

    cout << "Plaintext: " << plaintext << endl;
    cout << "Ciphertext: " << ciphertextStr << endl;
    cout << "Recovered: " << recoveredStr << endl;

    pause();
    return 0;
}
