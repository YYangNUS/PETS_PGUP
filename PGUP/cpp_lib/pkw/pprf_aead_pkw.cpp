/***********************************************************************************************************************
 * Copyright 2022 Younis Khalil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 **********************************************************************************************************************/
#include <iostream>
#include <iomanip>
#include <chrono>
#include "pprf_aead_pkw.h"
#include "pkw/exceptions.h"
#include "pprf/pprf_exceptions.h"
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include "cryptopp/hkdf.h"
#include "cryptopp/sha.h"

const int TAG_SIZE = 16;
using std::vector;
/**
 * from https://cryptopp.com/wiki/GCM_Mode#AEAD
 */
ciphertext PPRF_AEAD_PKW::wrap(Tag tag, vector<unsigned char> &header, vector<unsigned char> &key) {
    //std::cout << "\n\n***" << __PRETTY_FUNCTION__ << "***" << std::endl;    
    try {
        auto t1 = std::chrono::high_resolution_clock::now();      
// #ifdef INCLUDE_KDF
        //std::cout << "INCLUDE_KDF\n";
        SecureByteBuffer wrapping_key_tmp = pprf.eval(tag);
        SecureByteBuffer wrapping_key(wrapping_key_tmp);
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(wrapping_key.data(), wrapping_key.size(), wrapping_key_tmp.data(),wrapping_key_tmp.size(), nullptr, 0, nullptr, 0);
// #else 
        // SecureByteBuffer wrapping_key = pprf.eval(tag);
// #endif        
        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        vector<unsigned char> iv(16, 0);
        e.SetKeyWithIV(wrapping_key.data(), wrapping_key.size(), iv.data(), iv.size());
        ciphertext cipher;
        CryptoPP::AuthenticatedEncryptionFilter ef(e,
                                                   new CryptoPP::VectorSink(cipher), false,
                                                   TAG_SIZE /* MAC_AT_END */);
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, header.data(), header.size());
        ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

        // Confidential data comes after authenticated data.
        // This is a limitation due to CCM mode, not GCM mode.
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, key.data(), key.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
        auto t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double,std::milli> dt = t2-t1;
        std::cout << "--------------------------\n";
        std::cout << "Wrap time => " << std::fixed << std::setprecision(4) << dt.count() << " ms" << std::endl;
        std::cout << "--------------------------\n\n";
        return cipher;
    } catch (CryptoPP::Exception &e) {
        throw WrappingException();
    } catch (TagException &e) {
        throw IllegalTagException();
    }    
}

/**
 * from https://cryptopp.com/wiki/GCM_Mode#AEAD
 */
vector<unsigned char> PPRF_AEAD_PKW::unwrap(Tag tag, vector<unsigned char> &header, ciphertext &c) {    
    //std::cout << "\n\n***" << __PRETTY_FUNCTION__ << "***" << std::endl;    
    try {
        auto t1 = std::chrono::high_resolution_clock::now();
#ifdef INCLUDE_KDF
        //std::cout << "INCLUDE_KDF\n";
        SecureByteBuffer wrapping_key_tmp = pprf.eval(tag);
        SecureByteBuffer wrapping_key(wrapping_key_tmp);
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(wrapping_key.data(), wrapping_key.size(), wrapping_key_tmp.data(),wrapping_key_tmp.size(), nullptr, 0, nullptr, 0);
#else 
        SecureByteBuffer wrapping_key = pprf.eval(tag);
#endif
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        vector<unsigned char> iv(16, 0);
        d.SetKeyWithIV(wrapping_key.data(), wrapping_key.size(), iv.data(), iv.size());
        vector<unsigned char> enc(c.begin(), c.end() - TAG_SIZE);
        vector<unsigned char> mac(c.end() - TAG_SIZE, c.end());
        CryptoPP::AuthenticatedDecryptionFilter df(d,
                                                   NULL, CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                                   TAG_SIZE /* MAC_AT_END */);
        // The order of the following calls are important
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, mac.data(), mac.size());
        df.ChannelPut(CryptoPP::AAD_CHANNEL, header.data(), header.size());
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //   during ChannelMessageEnd()
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if (!df.GetLastResult()) {
            throw UnwrappingException();
        }

        // Remove data from channel
        vector<unsigned char> retrieved;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel(CryptoPP::DEFAULT_CHANNEL);
        size_t n = (size_t) df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0) {
            df.Get((byte *) retrieved.data(), n);
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double,std::milli> dt = t2-t1;
        std::cout << "--------------------------\n";
        std::cout << "Unwrap time => " << std::fixed << std::setprecision(4) << dt.count() << " ms" << std::endl;
        std::cout << "--------------------------\n\n";
        return retrieved;
    } catch (CryptoPP::Exception &e) {
        throw UnwrappingException();
    } catch (TagException &e) {
        throw IllegalTagException();
    }    
}
void PPRF_AEAD_PKW::punc(Tag tag) {    
    //std::cout << "\n\n***" << __PRETTY_FUNCTION__ << "***" << std::endl;    
    auto t1 = std::chrono::high_resolution_clock::now();
    pprf.punc(tag);
    auto t2 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double,std::milli> dt = t2-t1;
    std::cout << "--------------------------\n";
    std::cout << "Punc time => " << std::fixed << std::setprecision(4) << dt.count() << " ms" << std::endl;
    std::cout << "--------------------------\n\n";
}
long PPRF_AEAD_PKW::getNumPuncs() {
    return pprf.getNumPuncs();
}
/* Not needed because of use of SecureByteBuffer */
void PPRF_AEAD_PKW::secureTeardown() {
}
SecureByteBuffer PPRF_AEAD_PKW::serializeKey() {
    return pprf.serializeKey();
}
SecureByteBuffer PPRF_AEAD_PKW::serializeAndEncryptKey(const std::string &password) {
    auto serialized = serializeKey();
    return encryptExport(serialized, password);
}
PPRF_AEAD_PKW::PPRF_AEAD_PKW(int tagLen, int keyLen) : pprf(PPRFKey(keyLen, tagLen)) {}

PPRF_AEAD_PKW::PPRF_AEAD_PKW(SecureByteBuffer serializedKey) : pprf(PPRFKey::fromSerialized(serializedKey)) {}

std::shared_ptr<AbstractPKW<Tag, ciphertext>> PPRF_AEAD_PKW_Factory::fromSerialized(SecureByteBuffer &serialized) {
    return std::shared_ptr<AbstractPKW<Tag, ciphertext>>(new PPRF_AEAD_PKW(serialized));
}

// Derivation function
SecureByteBuffer PPRF_AEAD_PKW::Drv(const SecureByteBuffer& sk, const std::vector<unsigned char>& ad)
{
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    SecureByteBuffer newsk(sk);
    hkdf.DeriveKey(newsk.data(), newsk.size(), sk.data(), sk.size(), nullptr, 0, ad.data(), ad.size());
    return newsk;
}

SecureByteBuffer PPRF_AEAD_PKW::gensk(Tag tag)
{
   return pprf.eval(tag);
}