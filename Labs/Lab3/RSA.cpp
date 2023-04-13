#include <iostream>
using std::cerr;
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;


#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;


#include <string>
using std::string;
using std::wstring;


#include <cstdlib>
using std::exit;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;


#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;


#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cassert>

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;


#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

using namespace CryptoPP;
using namespace std;

// ========================== FUNCTIONS ==============================//

void SaveKey( const RSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void PrintByte(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    wcout << string_to_wstring(encoded) << endl;
}






// ========================== Main Program ==============================//

int main()
{
    setlocale(LC_ALL, "");
    try
    {
        // Generate keys
        AutoSeededRandomPool rng;
        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 1024 );
        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );
        // Secret to protect
        static const int SECRET_SIZE = 23;
        SecByteBlock plaintext (SECRET_SIZE);
        memset( plaintext, 'RSA Encryption Schemes', SECRET_SIZE );
        ////////////////////////////////////////////////
        // Encrypt
        RSAES_OAEP_SHA_Encryptor encryptor( publicKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != encryptor.FixedMaxPlaintextLength() );
        assert( SECRET_SIZE <= encryptor.FixedMaxPlaintextLength() );        

        // Create cipher text space
        size_t ecl = encryptor.CiphertextLength( plaintext.size() );
        assert( 0 != ecl );
        SecByteBlock ciphertext( ecl );

        // Paydirt
        encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );

        ////////////////////////////////////////////////
        // Decrypt
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != decryptor.FixedCiphertextLength() );
        assert( ciphertext.size() <= decryptor.FixedCiphertextLength() );        

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
        assert( 0 != dpl );
        SecByteBlock recovered( dpl );

        // Paydirt
        DecodingResult result = decryptor.Decrypt( rng,
            ciphertext, ciphertext.size(), recovered );

        // More sanity checks
        assert( result.isValidCoding );        
        assert( result.messageLength <=
            decryptor.MaxPlaintextLength( ciphertext.size() ) );
        assert( plaintext.size() == result.messageLength );

        // At this point, we can set the size of the recovered
        //  data. Until decryption occurs (successfully), we
        //  only know its maximum size
        recovered.resize( result.messageLength );

        // SecByteBlock is overloaded for proper results below
        assert( plaintext == recovered );

        cout << "Recovered plain text" << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }


}