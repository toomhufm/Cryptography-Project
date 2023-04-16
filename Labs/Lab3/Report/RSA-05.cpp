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

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
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

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;
#include <assert.h>



// ===================================================================== //

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

// ===================================================================== //
int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        RSA::PrivateKey priv;
        LoadPrivateKey("rsa-private.key",priv);
        RSA::PublicKey pub;
        LoadPublicKey("rsa-public.key",pub);
        string plain="Key load from file", cipher, recovered;
        cout << "Plain Text : " << plain << endl;


        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor enc( pub );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, enc,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        cout << "Cipher Text : " <<ToHex(cipher) << endl;
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( priv );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, dec,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        assert( plain == recovered );
        cout << "Recovered Text : " <<plain << endl;
    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }

	return 0;
}

