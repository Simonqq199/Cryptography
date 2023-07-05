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

#include "des.h"
using CryptoPP::DES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"

#ifdef _WIN32
// If we are on a Windows platform, we need these headers to ensure compatibility with the C library
#include <io.h> // Contains the _setmode() function which sets the file descriptor mode
#include <fcntl.h> // Contains the file control functions and constants such as _O_U16TEXT
#endif

#include <locale> // Contains locale-related functions and classes
#include <codecvt> // Contains codecvt-related functions and classes
using std::wcout; // Wide character version of cout
using std::wcin; // Wide character version of cin
using std::wstring; // Wide character string type
using std::wstring_convert; // String conversion utility
using std::codecvt_utf8; // UTF-8 codecvt facet

