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

#include "hrtimer.h"
using CryptoPP::ThreadUserTimer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

#include <string>
using std::string;

#include <iostream>
#include <fstream>
#include <codecvt>
#include <fcntl.h>
#include <locale>
#include <io.h>
using std::cout;
using std::endl;
using std::ifstream;
using std::ios;
using std::wstring;
using std::wstring_convert;
using std::codecvt_utf8;

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

void setup_utf16()
{
#ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
#elif _WIN32 // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif
}


const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;
const int rounds = 1000;

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
        string message = "";
        ifstream file;
        file.open("100MB.txt", ios::out | ios::app | ios::binary);
        if (file.is_open())
        {
            string line = "";
            while (getline(file, line))
            {
                message += line + "\n";
            }
            file.close();
        }

        // utf-16 message
        wstring wmessage = L"RSA mật mã học LAB03D";
        string utf16_message = wstring_to_string(wmessage);

        // Signer object
        RSASS<PSS, SHA1>::Signer signer(privateKey);

        // Create signature space
        size_t length = signer.MaxSignatureLength();
        SecByteBlock signature(length);

        // Verifier object
        RSASS<PSS, SHA1>::Verifier verifier(publicKey);

        // Start timer
        ThreadUserTimer timer;

        // Sign utf16_message
        double total_time = 0;
        for (int i = 0; i < rounds; i++) {
            timer.StartTimer();
            // Sign message
            signer.SignMessage(rng, (const byte*)utf16_message.c_str(), utf16_message.length(), signature);
            total_time += timer.ElapsedTimeAsDouble();
        }

        // Verify
        bool result = verifier.VerifyMessage((const byte*)utf16_message.c_str(), utf16_message.length(), signature, signature.size());

        // Result
        if (true == result) {
            cout << "Signature on message verified" << endl;
        }
        else {
            cout << "Message verification failed" << endl;
        }

        // Print timing information
        double CPB = total_time * cpuFreq / (rounds * utf16_message.size());
        double MPS = (rounds * utf16_message.size()) / (total_time * 1024 * 1024);
        cout << "UTF-16 case's performance: " << endl;
        cout << CPB << " Cycles per byte" << endl;
        cout << MPS << " MiB per second" << endl;

        // Sign message

        total_time = 0;
        for (int i = 0; i < rounds; i++) {
            timer.StartTimer();
            // Sign message
            signer.SignMessage(rng, (const byte*)message.c_str(), message.length(), signature);
            total_time += timer.ElapsedTimeAsDouble();
        }

        // Verify
        result = verifier.VerifyMessage((const byte*)message.c_str(), message.length(), signature, signature.size());

        // Result
        if (true == result) {
            cout << "Signature on message verified" << endl;
        }
        else {
            cout << "Message verification failed" << endl;
        }

        // Print timing information
        CPB = total_time * cpuFreq / (rounds * message.size());
        MPS = (rounds * message.size()) / (total_time * 1024 * 1024);
        cout << "100MB file input case's performance: " << endl;
        cout << CPB << " Cycles per byte" << endl;
        cout << MPS << " MiB per second" << endl;

    } // try

    catch (CryptoPP::Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    pause();

    return 0;
}