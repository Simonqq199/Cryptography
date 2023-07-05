#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA512;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;


#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "queue.h" // using for load functions 
using CryptoPP::ByteQueue;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::BufferedTransformation; // using for load function

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;
/* Convert to hex */
#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <assert.h>

/* Vietnamese support */

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif

/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* Integer convert */
#include <sstream>
using std::ostringstream;

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

/* convert string to wstring */
wstring ConvertStringtoWstring(const std::string& str)
{
    // Declare an object `converterX` of the `wstring_convert` class
    using convert_typeX = codecvt_utf8<wchar_t>;
    wstring_convert<convert_typeX, wchar_t> converterX;
    // Return the result of the conversion from a byte string to a wide string.
    return converterX.from_bytes(str);
}

/* convert wstring to string */
string ConvertWstringToString(const std::wstring& wstr)
{
    // Declare an object `converterX` of the `wstring_convert` class
    using convert_typeX = codecvt_utf8<wchar_t>;
    wstring_convert<convert_typeX, wchar_t> converterX;
    // Return the result of the conversion from a wide-character encoding to a byte string.
    return converterX.to_bytes(wstr);
}

void InputCiphertextFromFile(string& cipher)
{
    FileSource file("cipher-text.txt", true, new StringSink(cipher));
    // wcout << L"Ciphertext:"<< ConvertStringtoWstring(cipher) << endl;
}

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPrivateKey(const string& filename, RSA::PrivateKey& key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string& filename, RSA::PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

int main()
{
    // Set mode support Vietnamese
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
    try
    {
        AutoSeededRandomPool rng;

        // Load key from files 
        RSA::PrivateKey privateKey;
        LoadPrivateKey("rsa-private.key", privateKey);

        // Decryption
        string cipherHex, cipher, recovered; // ciphertext to decrypt
        cipherHex.clear();
        InputCiphertextFromFile(cipherHex);

        /* Decrypt */

            // Hex decode the input cipher
        cipher.clear();
        StringSource(cipherHex, true,
            new HexDecoder(new StringSink(cipher)));

        RSAES_OAEP_SHA_Decryptor d(privateKey);
        recovered.clear();
        StringSource(cipher, true,
            new PK_DecryptorFilter(rng, d,
                new StringSink(recovered)
            ) // PK_EncryptorFilter
        ); // StringSource

        wcout << "Recover text: " << ConvertStringtoWstring(recovered) << endl;
    }
    catch (CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

    pause();

}
