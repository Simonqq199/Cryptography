#include <bits/stdc++.h>

using namespace std;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include "cryptlib.h"
#include "md5.h"
#include "sha3.h"
#include "sha.h"
#include "shake.h"

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "files.h"
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

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

// convert wstring to string
wstring s2ws(const std::string& str)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.from_bytes(str);
}

// Convert wstring to string
string ws2s(const std::wstring& wstr)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.to_bytes(wstr);
}

// convert integer to wstring
wstring in2ws(const CryptoPP::Integer& t)
{
	ostringstream oss;
	oss.str("");
	oss.clear();
	oss << t;
	string encoded(oss.str());
	wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(encoded);
}

// convert byte string to hex wstring cryptopp::byte
void convertor(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
		new HexEncoder(
			new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	std::wcout << wstr << endl;
}

// convert byte string to hex wstring cryptopp::byte
wstring convertorForFile(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
		new HexEncoder(
			new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	return wstr;
}

//get message from console
string getMessageFromConsole()
{
	wstring winput;
	std::wcout << L"Plaintext: ";
	fflush(stdin);
	getline(wcin, winput);
	return ws2s(winput);
}



//select hash function
int selectHashFunction()
{
	std::wcout << L"Select hash function: " << endl;
	std::wcout << L"0. MD5" << endl;
	std::wcout << L"1. SHA224" << endl;
	std::wcout << L"2. SHA256" << endl;
	std::wcout << L"3. SHA384" << endl;
	std::wcout << L"4. SHA512" << endl;
	std::wcout << L"5. SHA3_224" << endl;
	std::wcout << L"6. SHA3_256" << endl;
	std::wcout << L"7. SHA3_384" << endl;
	std::wcout << L"8. SHA3_512" << endl;
	std::wcout << L"9. SHAKE128" << endl;
	std::wcout << L"10. SHAKE256" << endl;
	std::wcout << L"Your choice: ";

	int numberOfHashFunction;
	try
	{
		wcin >> numberOfHashFunction;
		return numberOfHashFunction;
	}
	catch (exception& exc)
	{
		std::wcout << L"Error in choosing hash function" << endl;
		std::wcout << L"Error: " << exc.what() << endl;
		exit(1);
	}
}


//create hash function
template <class HASH>
string hashFunc(const string& message)
{
	HASH hash;
	string digest;
	hash.Restart();
	hash.Update((const CryptoPP::byte*)message.data(), message.size());
	digest.resize(hash.DigestSize());
	hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size());
	return digest;
}

//create shake function
template <class SHAKE>
string shakeFunc(const string& message, int digestSize)
{
	SHAKE hash;
	string digest;
	hash.Restart();
	hash.Update((const CryptoPP::byte*)message.data(), message.size());
	digest.resize(digestSize);
	hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size());
	return digest;
}


//set up vietnamese language
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}


int main(int argc, char** argv)
{
	setUpVietnamese();

	//declare variables
	string digest = "", message = "";
	int digestSize;

	message = getMessageFromConsole();


	//selectHashFunction
	int typeOfHashFunction = selectHashFunction();
	if (typeOfHashFunction == 9 || typeOfHashFunction == 10)
	{
		std::wcout << L"Enter digest size: ";
		wcin >> digestSize;
	}

	switch (typeOfHashFunction)
	{
	case 0:
		digest = hashFunc<CryptoPP::MD5>(message);
		break;
	case 1:
		digest = hashFunc<CryptoPP::SHA224>(message);
		break;

	case 2:
		digest = hashFunc<CryptoPP::SHA256>(message);
		break;

	case 3:
		digest = hashFunc<CryptoPP::SHA384>(message);
		break;

	case 4:
		digest = hashFunc<CryptoPP::SHA512>(message);
		break;

	case 5:
		digest = hashFunc<CryptoPP::SHA3_224>(message);
		break;

	case 6:
		digest = hashFunc<CryptoPP::SHA3_256>(message);
		break;

	case 7:
		digest = hashFunc<CryptoPP::SHA3_384>(message);
		break;

	case 8:
		digest = hashFunc<CryptoPP::SHA3_512>(message);
		break;

	case 9:
		digest = shakeFunc<CryptoPP::SHAKE128>(message, digestSize);
		break;

	case 10:
		digest = shakeFunc<CryptoPP::SHAKE256>(message, digestSize);
		break;
	
	}
	std::wcout << L"----------------------------------------------------------------" << endl;
	std::wcout << L"Message: " << s2ws(message) << endl;
	std::wcout << L"Digest: ";
	convertor(digest);

	pause();

	return 0;
}