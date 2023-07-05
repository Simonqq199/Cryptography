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

void InputPlaintextFromFile(string& plain)
{
    FileSource file("plain-text.txt", true, new StringSink(plain));
    wcout << L"Plaintext:" << ConvertStringtoWstring(plain) << endl;
}

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
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
        // Generate keys
        AutoSeededRandomPool rng;

        // Load key from files
        RSA::PublicKey publicKey;
        LoadPublicKey("rsa-public.key", publicKey);

        // Input Plaintext
        string plain, cipher;
        wstring wplain;
        wcout << "Input Plaintext: ";
        fflush(stdin);
        getline(wcin, wplain);
        plain = ConvertWstringToString(wplain);
        string encoded = "";


        // Setup publicKey for Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey); // RSAES_PKCS1v15_Decrypt
        cipher.clear();
        // Create a pipelining for encryption
        StringSource(plain, true,
            new PK_EncryptorFilter(rng, e,
                new StringSink(cipher)
            ) // PK_EncryptorFilter
        ); // StringSource

        // Write cipher as hexa code
        encoded.clear();
        StringSource(cipher, true,
            new HexEncoder(new StringSink(encoded)));

        wcout << L"* Ciphertext: " << ConvertStringtoWstring(encoded) << endl;
    }
    catch (CryptoPP::Exception& e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

    pause();

}
