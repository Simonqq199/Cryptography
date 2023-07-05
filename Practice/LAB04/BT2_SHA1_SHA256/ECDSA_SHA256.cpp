#include <bits/stdc++.h>

#include <assert.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "aes.h"
using CryptoPP::AES;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA256;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#if _MSC_VER <= 1200 // VS 6.0
using CryptoPP::ECDSA<ECP, SHA256>;
using CryptoPP::DL_GroupParameters_EC<ECP>;
#endif

#include "oids.h"
using CryptoPP::OID;

using namespace CryptoPP;

string getMessageFromFile(string filename);

bool GeneratePrivateKey(const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key);
bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey);

void SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key);
void SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key);
void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key);
void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key);

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey& key);
void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey& key);
void PrintDomainParameters(const DL_GroupParameters_EC<ECP>& params);
void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey& key);
void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey& key);

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature);
bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature);

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

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{


    // Scratch result
    bool result = false;

    // Private and Public keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;

    /////////////////////////////////////////////
    // Generate Keys
    result = GeneratePrivateKey(CryptoPP::ASN1::secp256r1(), privateKey);
    assert(true == result);
    if (!result) { return -1; }

    result = GeneratePublicKey(privateKey, publicKey);
    assert(true == result);
    if (!result) { return -2; }

    // Sign and Verify a message      
    string message = getMessageFromFile("UIT.png");
    string signature;

    result = SignMessage(privateKey, message, signature);
    if (true == result)
        std::wcout << "Signed successfully\n";
    else
        std::wcout << "Failed while signing!\n";

    result = VerifyMessage(publicKey, message, signature);
    if (true == result)
        std::wcout << "Verified successfully\n";
    else
        std::wcout << "Failed verifying! Unauthentic\n";


    /////////////////////////////////////////////
    // Print Domain Parameters and Keys   
    PrintDomainParameters(publicKey);
    PrintPrivateKey(privateKey);
    PrintPublicKey(publicKey);

    /////////////////////////////////////////////
    // Save key in PKCS#9 and X.509 format    
    //SavePrivateKey( "ec.private.key", privateKey );
    //SavePublicKey( "ec.public.key", publicKey );

    /////////////////////////////////////////////
    // Load key in PKCS#9 and X.509 format     
    //LoadPrivateKey( "ec.private.key", privateKey );
    //LoadPublicKey( "ec.public.key", publicKey );

    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    // PrintDomainParameters( publicKey );
    // PrintPrivateKey( privateKey );
    // PrintPublicKey( publicKey );

    /////////////////////////////////////////////

    pause();

    return 0;
}

//get the message from the file
string getMessageFromFile(string filename)
{
    string plaintext;
    std::ifstream file(filename);
    if (file.is_open())
    {
        getline(file, plaintext);
        file.close();
    }
    else
    {
        std::wcout << L"Unable to open file!" << endl;
        exit(1);
    }
    return plaintext;
}


bool GeneratePrivateKey(const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));

    return key.Validate(prng, 3);
}

bool GeneratePublicKey(const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey)
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert(privateKey.Validate(prng, 3));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 3));

    return publicKey.Validate(prng, 3);
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA256>::PublicKey& key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP>& params)
{
    cout << endl;

    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;

    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;

    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;

    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl;
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;

    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;

    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;
}

void PrintPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl;
}

void PrintPublicKey(const ECDSA<ECP, SHA256>::PublicKey& key)
{
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl;
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey(const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SavePublicKey(const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string& filename, ECDSA<ECP, SHA256>::PublicKey& key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool SignMessage(const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
        new SignerFilter(prng,
            ECDSA<ECP, SHA256>::Signer(key),
            new StringSink(signature)
        ) // SignerFilter
    ); // StringSource

    return !signature.empty();
}

bool VerifyMessage(const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature)
{
    bool result = false;

    StringSource(signature + message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP, SHA256>::Verifier(key),
            new ArraySink((byte*)&result, sizeof(result))
        ) // SignatureVerificationFilter
    );

    return result;
}
