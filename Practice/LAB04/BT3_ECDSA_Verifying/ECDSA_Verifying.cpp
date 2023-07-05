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

//load the public key from file
void loadPublicKey(const string& filename, ECDSA<ECP, SHA1>::PublicKey& key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

// convert byte string to hex wstring cryptopp::byte
void convertor(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
		new HexEncoder(
			new StringSink(encodedCode)));
	wstring wstr = stringToWString(encodedCode);
	wcout << wstr << endl;
}

//get the plaintext from the file
string getMessageFromFile(string filename)
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

//get the signature from the file
void getSignatureFromFile(string filename, string& signature)
{
	ifstream ifs(filename);
	if (ifs.is_open())
	{
		string line;
		while (ifs.good())
		{
			getline(ifs, line);
			signature += line;
		}
		ifs.close();
	}
	else
	{
		wcout << "Cannot open file " << stringToWString(filename) << "!" << endl;
		exit(1);
	}
}

//function to verify the signature
bool verifyMessage(const ECDSA<ECP, SHA1>::PublicKey& publicKey, const string& message, const string& signature)
{
	bool result = false;
	StringSource(signature + message, true,
		new SignatureVerificationFilter(
			ECDSA<ECP, SHA1>::Verifier(publicKey),
			new ArraySink((CryptoPP::byte*)&result, sizeof(result))));
	return result;
}

//function to set up the verification
void setUpVerification(string filePublicKey, string fileMessage, string fileSignature)
{
	ECDSA<ECP, SHA1>::PublicKey publicKey;

	loadPublicKey(filePublicKey, publicKey);

	string message = getMessageFromFile(fileMessage);

	string signature;
	getSignatureFromFile(fileSignature, signature);

	if (verifyMessage(publicKey, message, signature) == false)
	{
		wcout << L"Verification failed!" << endl;
		exit(1);
	}

	//printDomainParameters(publicKey);
	//printPublicKey(publicKey);
	wcout << L"Signature: ";
	convertor(signature);
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
	string filePublicKey = "." + slash + "eccPublic.key";
	string fileMessage = "." + slash + fileName;
	string fileSignature = "." + slash + fileSignatureName;

	wcout << "Verifying " << stringToWString(fileName) << " file\n";
	try
	{
		setUpVerification(filePublicKey, fileMessage, fileSignature);
		wcout << L"Message verified successfully!" << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		wcout << L"Error when verifying signature!" << endl;
		wcout << e.what() << endl;
		exit(1);
	}

	pause();

	return 0;
}
