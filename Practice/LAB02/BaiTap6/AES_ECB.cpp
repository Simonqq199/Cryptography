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

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"


int main(int argc, char** argv) {
    using namespace std;
    using namespace CryptoPP;

    // Generate a random key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());

    // Print key in hexadecimal format
    string encoded;
    ArraySource(key, key.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "key: " << encoded << endl;

    // Plaintext to be encrypted
    string plaintext = "ECB Mode Test";

    // Print plaintext
    cout << "plaintext: " << plaintext << endl;

    // Encrypt
    ECB_Mode< AES >::Encryption encryptor;
    encryptor.SetKey(key, key.size());

    string ciphertext;
    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    // Print ciphertext in hexadecimal format
    encoded.clear();
    StringSource(ciphertext, true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "ciphertext: " << encoded << endl;

    // Decrypt
    ECB_Mode< AES >::Decryption decryptor;
    decryptor.SetKey(key, key.size());

    string recovered;
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(recovered)
        )
    );

    // Print recovered plaintext
    cout << "recovered plaintext: " << recovered << endl;
    system("pause");
    return 0;
}
