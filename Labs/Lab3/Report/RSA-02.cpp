// Sample.cpp

#include "stdafx.h"

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <locale>
using std::wstring_convert;

#include <codecvt>
using std::codecvt_utf8;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <string>
using std::string;
using std::wstring;
#include <exception>
using std::exception;
#include <iomanip>
using std::hex;
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>



// ===================================================================== //


string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

// ===================================================================== //
int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 1024 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain="Encrypt with Public Key", cipher, recovered;
        cout << "Plain Text : " << plain << endl;

        ///////////////////////////////////////
        // Generated Parameters
        const Integer n = parameters.GetModulus();
        const Integer p = parameters.GetPrime1();
        const Integer q = parameters.GetPrime2();
        const Integer d = parameters.GetPrivateExponent();
        const Integer e = parameters.GetPublicExponent();

        ///////////////////////////////////////
        // Dump
        cout << "RSA Parameters:" << endl;
        cout << " n: " << n << endl;
        cout << " p: " << p << endl;
        cout << " q: " << q << endl;
        cout << " d: " << d << endl;
        cout << " e: " << e << endl;
        cout << endl;

        Integer m((const byte *)plain.data(), plain.size());

        ////////////////////////////////////////////////
        // Encryption
        Integer c = publicKey.ApplyFunction(m);
        cout << "Cipher: " << hex << c << endl;
        ////////////////////////////////////////////////


        ////////////////////////////////////////////////
        // Decryption
        Integer r = privateKey.CalculateInverse(rng, c);
        size_t req = r.MinEncodedSize();
        recovered.resize(req);

        r.Encode((byte *) &recovered[0], recovered.size());
        cout << "Recovered: " << recovered << endl;
    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }

	return 0;
}

