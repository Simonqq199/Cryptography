#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cout;
using std::cin;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::byte;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"

#include "assert.h"

using namespace CryptoPP;
using namespace std;

int main()
{
    // Key and IV setup
    // AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    // bit). This key is secretly exchanged between two parties before communication 
    // begins. DEFAULT_KEYLENGTH= 16 bytes
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    // Message to be encrypted
    std::string plaintext = "GCM Mode Test";

    // Encryption
    CryptoPP::GCM< CryptoPP::AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    std::string ciphertext;
    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::AuthenticatedEncryptionFilter(e,
            new CryptoPP::StringSink(ciphertext)
        ) // AuthenticatedEncryptionFilter
    ); // StringSource

    // Decryption
    CryptoPP::GCM< CryptoPP::AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    std::string decryptedtext;
    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::AuthenticatedDecryptionFilter(d,
            new CryptoPP::StringSink(decryptedtext)
        ) // AuthenticatedDecryptionFilter
    ); // StringSource

    std::cout << "key: ";
    for (int i = 0; i < sizeof(key); i++) {
        std::cout << std::hex << (int)key[i];
    }
    std::cout << std::endl;

    std::cout << "iv: ";
    for (int i = 0; i < sizeof(iv); i++) {
        std::cout << std::hex << (int)iv[i];
    }
    std::cout << std::endl;

    std::cout << "plaintext: " << plaintext << std::endl;
    std::cout << "ciphertext: " << ciphertext << std::endl;
    std::cout << "recovered text: " << decryptedtext << std::endl;

    system("pause");
}
