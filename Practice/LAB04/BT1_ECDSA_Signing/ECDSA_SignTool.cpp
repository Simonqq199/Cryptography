#include <bits/stdc++.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "oids.h"
using CryptoPP::OID;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#define nValue 10000

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

/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

/* Integer convert */
#include <sstream>
using std::ostringstream;


// convert wstring to string
/* convert string to wstring */
wstring stringToWString(const std::string& str)
{
	// Declare an object `converterX` of the `wstring_convert` class
	using convert_typeX = codecvt_utf8<wchar_t>;
	wstring_convert<convert_typeX, wchar_t> converterX;
	// Return the result of the conversion from a byte string to a wide string.
	return converterX.from_bytes(str);
}

/* convert wstring to string */
string wstringToString(const std::wstring& wstr)
{
	// Declare an object `converterX` of the `wstring_convert` class
	using convert_typeX = codecvt_utf8<wchar_t>;
	wstring_convert<convert_typeX, wchar_t> converterX;
	// Return the result of the conversion from a wide-character encoding to a byte string.
	return converterX.to_bytes(wstr);
}

// convert integer to wstring
wstring integerToWString(const CryptoPP::Integer& t)
{
	std::ostringstream oss;
	oss.str("");
	oss.clear();
	oss << t;
	std::string encoded(oss.str());
	std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(encoded);
}

//load the private key from file
void loadPrivateKey(const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

//get the plaintext from the file
string getPlaintextFromFile(string filename)
{
	string plaintext;
	ifstream file(filename);
	if (file.is_open())
	{
		getline(file, plaintext);
		file.close();
	}
	else
	{
		wcout << L"Unable to open file!" << endl;
		exit(1);
	}
	return plaintext;
}

//function to sign the message
string signMessage(const string& message, const ECDSA<ECP, SHA1>::PrivateKey& privateKey)
{
	AutoSeededRandomPool prng;
	string signature;
	signature.clear();

	StringSource(message, true,
		new SignerFilter(prng,
			ECDSA<ECP, SHA1>::Signer(privateKey),
			new StringSink(signature)));
	return signature;
}

// convert byte string to hex wstring cryptopp::byte
void print(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
		new HexEncoder(
			new StringSink(encodedCode)));
	wstring wstr = stringToWString(encodedCode);
	wcout << wstr << endl;
}

void setUpSignature(string filePrivateKey, string fileMessage, string& signature)
{
	ECDSA<ECP, SHA1>::PrivateKey privateKey;

	loadPrivateKey(filePrivateKey, privateKey);

	string message = getPlaintextFromFile(fileMessage);
	double timeCounter = 0.0;

	signature = signMessage(message, privateKey);
	if (signature.empty())
	{
		wcout << L"Signature is empty!" << endl;
		exit(1);
	}

	wcout << L"Signature: ";
	print(signature);
}

// function to sign the file
void putSignatureToFile(string filename, const string& signature)
{
	ofstream file(filename);
	try
	{
		file << signature;
		file.close();
	}
	catch (const std::exception& e)
	{
		wcout << e.what() << '\n';
		exit(1);
	}
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

	string signature;
	string slash;

#ifdef _WIN32
	slash = '\\';
#elif __linux__
	slash = '/';
#endif


	string fileName = "UIT.png";
	string fileSignatureName = "signature.txt";
	string filePrivateKey = "." + slash + "eccPrivate.key";
	string fileMessage = "." + slash + fileName;
	string fileSignature = "." + slash + fileSignatureName;

	wcout << "Signing " << stringToWString(fileName) << " file\n";
	try
	{
		setUpSignature(filePrivateKey, fileMessage, signature);
		putSignatureToFile(fileSignature, signature);
		wcout << L"Signature saved successfully in " << stringToWString(fileSignatureName) << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		wcout << L"Error when signing message!" << endl;
		wcout << e.what() << endl;
		exit(1);
	}

	pause();

	return 0;
}
