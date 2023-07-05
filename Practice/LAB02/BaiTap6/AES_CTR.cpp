#include <iostream>
#include <string>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

int main(int argc, char** argv) {
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
    string plaintext = "CTR Mode Test";

    // Print plaintext
    cout << "plaintext: " << plaintext << endl;

    // Encrypt
    CTR_Mode< AES >::Encryption encryptor;
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
    CTR_Mode< AES >::Decryption decryptor;
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
    return 0;
}

