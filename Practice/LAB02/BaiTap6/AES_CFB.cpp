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

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]) {
    using namespace std;
    using namespace CryptoPP;

    // Generate a random key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    // Print key and IV in hexadecimal format
    string encoded;
    ArraySource(key, key.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "key: " << encoded << endl;

    encoded.clear();
    ArraySource(iv, iv.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        )
    );
    cout << "IV: " << encoded << endl;

    // Plaintext to be encrypted
    string plaintext = "CFB Mode Test";

    // Print plaintext
    cout << "plaintext: " << plaintext << endl;

    // Encrypt
    CFB_Mode< AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

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
    CFB_Mode< AES >::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

    string recovered;
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(recovered)
        )
    );

    // Print recovered plaintext
    cout << "recovered plaintext: " << recovered << endl;
    system("pause");
}