

#ifndef _AES_FULLMODE_CPP
#define _AES_FULLMODE_CPP

#include "cryptopp/osrng.h"
using CryptoPP::byte;
using CryptoPP::SecByteBlock;
#include <iostream>
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector; 
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include <cryptopp/xts.h>
using CryptoPP::XTS;
#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/secblock.h>
using CryptoPP::RoundUpToMultipleOf;
using CryptoPP::AlignedSecByteBlock;

#include "cryptopp/hrtimer.h"
using CryptoPP::ThreadUserTimer;

using namespace CryptoPP;

// ============================     AES CLASSES    ====================================//

enum class MODE
{
    ECB,
    CBC,
    OFB,
    CFB,
    CTR,
    XTS,
    CCM,
    GCM
};
class AESProgram
{
    ECB_Mode<AES>::Encryption ECB_ENC;
    ECB_Mode<AES>::Decryption ECB_DEC;
    /*********************************/
    CBC_Mode<AES>::Encryption CBC_ENC;
    CBC_Mode<AES>::Decryption CBC_DEC;
    /*********************************/
    OFB_Mode<AES>::Encryption OFB_ENC;
    OFB_Mode<AES>::Decryption OFB_DEC;
    /*********************************/
    CFB_Mode<AES>::Encryption CFB_ENC;
    CFB_Mode<AES>::Encryption CFB_DEC;
    /*********************************/
    CTR_Mode<AES>::Encryption CTR_ENC;
    CTR_Mode<AES>::Encryption CTR_DEC;
    /*********************************/
    XTS<AES>::Encryption XTS_ENC;
    XTS<AES>::Encryption XTS_DEC;
    /*********************************/
    CCM<AES, 16>::Encryption CCM_ENC;
    CCM<AES, 16>::Encryption CCM_DEC;
    /*********************************/
    GCM<AES,GCM_2K_Tables>::Encryption GCM_ENC;
    GCM<AES,GCM_2K_Tables>::Decryption GCM_DEC;
public:
    /*********************************\
    \*********************************/
    void Encryption_ECB(string &cipher, const string &plain, const SecByteBlock &key)
    {
        ECB_ENC.SetKey(key, key.size());
        StringSource ss(plain, true, new StreamTransformationFilter(ECB_ENC, new StringSink(cipher)));
        Benchmark(ECB_ENC);
    }
    void Decryption_ECB(string &cipher, const string &plain, const SecByteBlock &key)
    {
        ECB_DEC.SetKey(key, key.size());
        StringSource ss(plain, true, new StreamTransformationFilter(ECB_DEC, new StringSink(cipher)));
        Benchmark(ECB_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_CBC(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CBC_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CBC_ENC, new StringSink(cipher)));
        Benchmark(CBC_ENC);
    }
    void Decryption_CBC(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CBC_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CBC_DEC, new StringSink(cipher)));
        Benchmark(CBC_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_OFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        OFB_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(OFB_ENC, new StringSink(cipher)));
        Benchmark(OFB_ENC);
    }
    void Decryption_OFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        OFB_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(OFB_DEC, new StringSink(cipher)));
        Benchmark(OFB_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_CFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CFB_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CFB_ENC, new StringSink(cipher)));
        Benchmark(CFB_ENC);
    }
    void Decryption_CFB(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CFB_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CFB_DEC, new StringSink(cipher)));
        Benchmark(CFB_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_CTR(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CTR_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CTR_ENC, new StringSink(cipher)));
        Benchmark(CTR_ENC);
    }
    void Decryption_CTR(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CTR_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(CTR_DEC, new StringSink(cipher)));
        Benchmark(CTR_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_XTS(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        XTS_ENC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(XTS_ENC, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
        Benchmark(XTS_ENC);
    }
    void Decryption_XTS(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        XTS_DEC.SetKeyWithIV(key, key.size(), iv);
        StringSource ss(plain, true, new StreamTransformationFilter(XTS_DEC, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
        Benchmark(XTS_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_CCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CCM_ENC.SetKeyWithIV(key, key.size(), iv);
        CCM_ENC.SpecifyDataLengths(0, plain.length(), 0);
        StringSource ss(plain, true, new AuthenticatedEncryptionFilter(CCM_ENC, new StringSink(cipher)));
        Benchmark(CCM_ENC);
    }
    void Decryption_CCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
    {
        CCM_DEC.SetKeyWithIV(key, key.size(), iv);
        CCM_ENC.SpecifyDataLengths(0, plain.length() - 16, 0);
        StringSource ss(plain, true, new AuthenticatedDecryptionFilter(CCM_DEC, new StringSink(cipher)));
        Benchmark(CCM_DEC);
    }
    /*********************************\
    \*********************************/
    void Encryption_GCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv){
        GCM_ENC.SetKeyWithIV(key,key.size(),iv);
        //const int TAG_SIZE = 12;
        GCM_ENC.SpecifyDataLengths(0,plain.length(),0);
        StringSource ss( plain, true,new AuthenticatedEncryptionFilter( GCM_ENC,new StringSink(cipher), false)); 
        Benchmark(GCM_ENC);
    }
    void Decryption_GCM(string &cipher, const string &plain, const SecByteBlock &key, const SecByteBlock &iv){
        GCM_DEC.SetKeyWithIV(key,key.size(),iv);
       // const int TAG_SIZE = 12;
        AuthenticatedDecryptionFilter df( GCM_DEC,new StringSink(cipher)); 
        StringSource ss(plain, true,new Redirector(df /*, PASS_EVERYTHING */)); 
        Benchmark(GCM_DEC);
    }

    /*********************************\
    \*********************************/
    string ToHex(const string &text)
    {
        string encoded;
        encoded.clear();
        StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
        return encoded;
    }
    string Encryption(const string &plain, MODE CipherMode, const SecByteBlock &key, const SecByteBlock &iv)
    {
        string cipher;
        try
        {
            switch (CipherMode)
            {
            case MODE::ECB:
                Encryption_ECB(cipher, plain, key);
                break;
            case MODE::CBC:
                Encryption_CBC(cipher, plain, key, iv);
                break;
            case MODE::OFB:
                Encryption_OFB(cipher, plain, key, iv);
                break;
            case MODE::CFB:
                Encryption_CFB(cipher, plain, key, iv);
                break;
            case MODE::CTR:
                Encryption_CTR(cipher, plain, key, iv);
                break;
            case MODE::XTS:
                Encryption_XTS(cipher, plain, key, iv);
                break;
            case MODE::CCM:
                Encryption_CCM(cipher, plain, key, iv);
                break;
            case MODE::GCM:
                Encryption_GCM(cipher, plain, key, iv);
                break;
            default:
                cerr << "Not recognizing this mode!" << endl;
                exit(1); // StringSource
            }
        }
        catch (const CryptoPP::Exception &e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
        return cipher;
    }
    string Decryption(const string &cipher, MODE CipherMode, const SecByteBlock &key, const SecByteBlock &iv)
    {
        string recovered;
        try
        {
            switch (CipherMode)
            {
            case MODE::ECB:
                Decryption_ECB(recovered, cipher, key);
                break;
            case MODE::CBC:
                Decryption_CBC(recovered, cipher, key, iv);
                break;
            case MODE::OFB:
                Decryption_OFB(recovered, cipher, key, iv);
                break;
            case MODE::CFB:
                Decryption_CFB(recovered, cipher, key, iv);
                break;
            case MODE::CTR:
                Decryption_CTR(recovered, cipher, key, iv);
                break;
            case MODE::XTS:
                Decryption_XTS(recovered, cipher, key, iv);
                break;
            case MODE::CCM:
                Decryption_CCM(recovered, cipher, key, iv);
                break;
            case MODE::GCM:
                Decryption_GCM(recovered, cipher, key, iv);
            default:
                cerr << "Not recognizing this mode!" << endl;
                exit(1); // StringSource
            }
        }
        catch (const CryptoPP::Exception &e)
        {
            cerr << e.what() << endl;
            exit(1);
        }
        return recovered;
    }
    void Benchmark(StreamTransformation &cipher)
    {
        AutoSeededRandomPool prng;
        const int BUF_SIZE = RoundUpToMultipleOf(2048U,dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());
        const double runTimeInSeconds = 3.0;
        AlignedSecByteBlock buf(BUF_SIZE);
        prng.GenerateBlock(buf, buf.size());

        double elapsedTimeInSeconds;
        unsigned long i=0, blocks=1;

        ThreadUserTimer timer;
        timer.StartTimer();

        do
        {
            blocks *= 2;
            for (; i<blocks; i++)
                cipher.ProcessString(buf, BUF_SIZE);
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        }
        while (elapsedTimeInSeconds < runTimeInSeconds);
        const double cpuFreq = 3.3 * 1000 * 1000 * 1000;
        const double bytes = static_cast<double>(BUF_SIZE) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;
        wcout << "  " << ghz << " GHz cpu frequency"  << std::endl;
        wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }

};

#endif
