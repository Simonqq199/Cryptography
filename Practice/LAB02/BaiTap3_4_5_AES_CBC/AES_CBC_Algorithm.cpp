#include "UnicodeEncryption.h"

// Convert wstring to string
string wstring_to_string(wstring wstr)
{
	// Define the type of codecvt
	using convert_type = codecvt_utf8<wchar_t>;

	// Create an instance of a converter with the defined codecvt type and wchar_t
	wstring_convert<convert_type, wchar_t> converter;

	// Use the converter to convert the wstring to a UTF-8 encoded string
	return converter.to_bytes(wstr);
}

// Convert string to wstring
wstring string_to_wstring(string str)
{
	// Define the type of codecvt
	using convert_type = codecvt_utf8<wchar_t>;

	// Create an instance of a converter with the defined codecvt type and wchar_t
	wstring_convert<convert_type, wchar_t> converter;

	// Use the converter to convert the UTF-8 encoded string to a wstring
	return converter.from_bytes(str);
}


void unicodeSupport()
{
#ifdef	_WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#endif
}

int main(int argc, char* argv[])
{
	wcout << "Encryption using AES, CBC mode (Unicode support)\n";


	// Manually input SK and IV
	string key_str, iv_str;
	wcout << "Inputting secret key: ";
	getline(cin, key_str);
	wcout << "Inputting initialization vector: ";
	getline(cin, iv_str);

	// Convert the key and IV from hex strings to byte arrays
	SecByteBlock key((const unsigned char*)key_str.data(), key_str.size() / 2);
	byte iv[AES::BLOCKSIZE];
	HexDecoder decoder;
	decoder.Put((const unsigned char*)iv_str.data(), iv_str.size());
	decoder.MessageEnd();
	decoder.Get(iv, sizeof(iv));

	// Set the console's input and output file descriptor to use the UTF-16 encoding format.
	unicodeSupport();

	// Get plain text
	wstring text;
	string plain;
	wcout << "Inputting plaintext: ";
	getline(wcin, text);
	plain = wstring_to_string(text);

	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	// wcout << endl << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	// wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		// cout << "plain text: " << plain << endl;

		CBC_Mode< AES >::Encryption encrypt;
		encrypt.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true,
			new StreamTransformationFilter(encrypt,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& error)
	{
		cerr << error.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "------------Result--------------";
	wcout << endl << "Cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption decrypt;
		decrypt.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
			new StreamTransformationFilter(decrypt,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
	}
	catch (const CryptoPP::Exception& error)
	{
		cerr << error.what() << endl;
		exit(1);
	}
	sysyem("pause");
	/*********************************\
	\*********************************/

	return 0;
}
