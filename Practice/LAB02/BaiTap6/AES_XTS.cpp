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

#include "xts.h"

#include "assert.h"

using namespace CryptoPP;
using namespace std;

int main()
{
    // Key and IV setup
    CryptoPP::byte key[32], iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    // Message to be encrypted
    std::string plaintext = "XTS Mode Test, hello world, hello world, hello world!";

    // Encryption
    CryptoPP::XTS_Mode< CryptoPP::AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    std::string ciphertext;
    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::StreamTransformationFilter(e,
            new CryptoPP::StringSink(ciphertext)
        ) // StreamTransformationFilter
    ); // StringSource

    // Decryption
    CryptoPP::XTS_Mode< CryptoPP::AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    std::string decryptedtext;
    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(decryptedtext)
        ) // StreamTransformationFilter
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
