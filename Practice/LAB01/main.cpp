// Standard includes
#include <iostream>
#include <codecvt>
#include <locale>
#include <fcntl.h>

// Time includes
#include <chrono>

// Define time variables
std::chrono::_V2::system_clock::time_point begin, end;
std::chrono::microseconds duration;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

// CryptoPP includes
#include <cryptlib.h>
#include <hex.h>
#include <secblock.h>
#include <modes.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>

// Define std environment
using std::string;
using std::cout;
using std::endl;
using std::cerr;
using std::wstring;
using std::wstring_convert;
using std::codecvt_utf8;


// Define CryptoPP environment
using CryptoPP::AES;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::SecByteBlock;
using CryptoPP::byte;
using CryptoPP::StringSink;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::StreamTransformation;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::RoundUpToMultipleOf;
using CryptoPP::AlignedSecByteBlock;

// Define AES mode
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;

// Not supported by current CryptoPP library 
// using CryptoPP::XTS_Mode;	
// using CryptoPP::CCM_Mode;	
// using CryptoPP::GCM_Mode;

string wstring_to_string(wstring wstr)
{
	using convert_type = codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;
    return converter.to_bytes(wstr);
}

wstring string_to_wstring(string str)
{
	using convert_type = codecvt_utf8<wchar_t>;
	wstring_convert<convert_type, wchar_t> converter;
	return converter.from_bytes(str);
}

void setup_utf16()
{
	#ifdef  __linux__ // For linux
		setlocale(LC_ALL, "");
	#elif _WIN32 // For windows
		_setmode(_fileno(stdin), _O_U16TEXT);
		_setmode(_fileno(stdout), _O_U16TEXT);
	#endif
}

string CBC_encrypt(string &plain, SecByteBlock key, byte *iv) {

    string cipher;
    string output;

    try {
        CBC_Mode<AES>::Encryption e(key, key.size(), iv);
        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (Exception &exception) {
        cerr << exception.what() << endl;
        exit(1);
    }

    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(output)
        ) // HexEncoder
    ); // StringSource

    return output;
}

string ECB_encrypt(string text, byte key[], int keySize) {
    string cipher = "";
    try
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, keySize);
        StringSource(text, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return cipher;
}

string OFB_encrypt(string &plain, SecByteBlock key, byte *iv) {
    string cipher;
    string output;

    try {
        OFB_Mode<AES>::Encryption e(key, key.size(), iv);

        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (Exception &exception) {
        cerr << exception.what() << endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}

string CFB_encrypt(string &plain, SecByteBlock key, byte *iv) {
    string cipher;
    string output;

    try {
        CFB_Mode<AES>::Encryption e(key, key.size(), iv);
        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (Exception &exception) {
        cerr << exception.what() << endl;
        exit(1);
    }

    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}

string CTR_encrypt(string &plain, SecByteBlock key, byte *iv) {
    string cipher;
    string output;

    try {
        CTR_Mode<AES>::Encryption e(key, key.size(), iv);

        StringSource(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (Exception &exception) {
        cerr << exception.what() << endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}

int main(int argc, char* argv[]) {

	// Prepare random number generator
	AutoSeededRandomPool prng;
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());
	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plaintext1 = "test"; 
    float size_of_plaintext1 = 0.00000381469;
    wstring temp_plaintext2 = L"Đây là đoạn văn bản dùng để kiểm tra tốc độ của các chế độ mã hóa của AES";
    string plaintext2 = wstring_to_string(temp_plaintext2);
    float size_of_plaintext2 = 0.00008487701;
	float size_of_plaintext3 = 1.43051147;
    string cipher, recovered;

    cout << "=== Mode CBC ===" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CBC_encrypt(plaintext1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);
    
    cout << "   [+] Less than 64-bit data: "<< size_of_plaintext1 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext1 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CBC_encrypt(plaintext2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] utf-16 data: "<< size_of_plaintext2 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext2 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CBC_encrypt(plaintext3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] over 1 MiB data: "<< size_of_plaintext3 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext3 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    //////////////////////////////

    cout << endl << "=== Mode ECB ===" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = ECB_encrypt(plaintext1, key, key.size());
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);
    
    cout << "   [+] Less than 64-bit data: "<< size_of_plaintext1 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext1 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = ECB_encrypt(plaintext2, key, key.size());
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] utf-16 data: "<< size_of_plaintext2 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext2 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = ECB_encrypt(plaintext3, key, key.size());
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] over 1 MiB data: "<< size_of_plaintext3 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext3 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    ///////////////////////

    cout << endl << "=== Mode OFB ===" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = OFB_encrypt(plaintext1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);
    
    cout << "   [+] Less than 64-bit data: "<< size_of_plaintext1 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext1 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = OFB_encrypt(plaintext2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] utf-16 data: "<< size_of_plaintext2 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext2 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = OFB_encrypt(plaintext3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] over 1 MiB data: "<< size_of_plaintext3 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext3 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    //////////////////////////

    cout << "=== Mode CFB ===" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CFB_encrypt(plaintext1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);
    
    cout << "   [+] Less than 64-bit data: "<< size_of_plaintext1 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext1 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CFB_encrypt(plaintext2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] utf-16 data: "<< size_of_plaintext2 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext2 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CFB_encrypt(plaintext3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] over 1 MiB data: "<< size_of_plaintext3 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext3 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    ///////////////////

    cout << "=== Mode CTR ===" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CTR_encrypt(plaintext1, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);
    
    cout << "   [+] Less than 64-bit data: "<< size_of_plaintext1 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext1 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CTR_encrypt(plaintext2, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] utf-16 data: "<< size_of_plaintext2 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext2 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

    begin = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
	    cipher = CTR_encrypt(plaintext3, key, iv);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin);

    cout << "   [+] over 1 MiB data: "<< size_of_plaintext3 / (duration.count()) << " MiB per second (MiB) and " << (size_of_plaintext3 * 1048576) /  (duration.count()) * cpuFreq << " cycles per byte (cpb)" << endl;

	return 0;
}