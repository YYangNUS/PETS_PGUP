#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <pkw/exceptions.h>
#include <pkw/pkw.h>
#include <pkw/pprf_aead_pkw.h>
#include <stdio.h>
#include <string.h>
#include <random>
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <pkw/pprf_aead_pkw.h>

#define SALT_LENGTH 16

#define CHECK_ERROR(cond, msg) \
    if (!(cond)) { \
        fprintf(stderr, "%s\n", msg); \
        ERR_print_errors_fp(stderr); \
    }

void print_hex(const std::vector<unsigned char>& v) {
    for (auto val : v)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val);
    std::cout << std::endl;
}

void print_hex_new(const std::string& label, const std::vector<unsigned char>& v) {
    std::cout << label << ": ";
    for (auto val : v)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val);
    std::cout << std::endl;
}

std::vector<unsigned char> generate_random_data(size_t length) {
    std::vector<unsigned char> data(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < length; ++i) {
        data[i] = static_cast<unsigned char>(dis(gen));
    }
    return data;
}

void print(const std::vector<unsigned char> &v) {
    for (auto val: v)
        std::cout << val;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

std::string toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

std::vector<unsigned char> generateSUTI(size_t length = 32) {
    std::vector<unsigned char> suti(length);
    if (RAND_bytes(suti.data(), suti.size()) != 1) {
        handleErrors();
    }
    return suti;
}

EC_KEY* generateKeyPair() {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); 
    if (!key) handleErrors();

    if (EC_KEY_generate_key(key) != 1) handleErrors();

    return key;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> encapsulateKey(EC_KEY* publicKey) {
    const EC_POINT* pubPoint = EC_KEY_get0_public_key(publicKey);
    const EC_GROUP* group = EC_KEY_get0_group(publicKey);

    EC_KEY* ephemeralKey = generateKeyPair();
    const EC_POINT* ephemeralPubPoint = EC_KEY_get0_public_key(ephemeralKey);

    std::vector<unsigned char> sharedKey(32); 
    if (ECDH_compute_key(sharedKey.data(), sharedKey.size(), pubPoint, ephemeralKey, nullptr) <= 0) {
        handleErrors();
    }

    unsigned char* buf = nullptr;
    int len = EC_POINT_point2buf(group, ephemeralPubPoint, POINT_CONVERSION_UNCOMPRESSED, &buf, nullptr);
    if (len <= 0) handleErrors();

    std::vector<unsigned char> encapsulatedKey(buf, buf + len);
    OPENSSL_free(buf);
    EC_KEY_free(ephemeralKey);

    return {encapsulatedKey, sharedKey};
}

std::vector<unsigned char> decryptSUTI(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& ck) {
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + 16);
    std::vector<unsigned char> actual_ciphertext(ciphertext.begin() + 16, ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, ck.data(), iv.data()) != 1) handleErrors();

    std::vector<unsigned char> plaintext(actual_ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext.data(), actual_ciphertext.size()) != 1) handleErrors();
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) handleErrors();
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::vector<unsigned char> encryptSUTI(const std::vector<unsigned char>& suti, const std::vector<unsigned char>& ck) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    std::vector<unsigned char> iv(16); 
    if (RAND_bytes(iv.data(), iv.size()) != 1) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, ck.data(), iv.data()) != 1) handleErrors();

    std::vector<unsigned char> ciphertext(suti.size() + 16);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, suti.data(), suti.size()) != 1) handleErrors();
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());
    return ciphertext;
}

std::vector<unsigned char> decapsulateKey(EC_KEY* privateKey, const std::vector<unsigned char>& encapsulatedKey) {
    const EC_GROUP* group = EC_KEY_get0_group(privateKey);
    EC_POINT* ephemeralPubPoint = EC_POINT_new(group);

    if (!EC_POINT_oct2point(group, ephemeralPubPoint, encapsulatedKey.data(), encapsulatedKey.size(), nullptr)) {
        handleErrors();
    }

    std::vector<unsigned char> sharedKey(32);
    if (ECDH_compute_key(sharedKey.data(), sharedKey.size(), ephemeralPubPoint, privateKey, nullptr) <= 0) {
        handleErrors();
    }

    EC_POINT_free(ephemeralPubPoint);
    return sharedKey;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> f5(
    const std::vector<unsigned char>& rk,
    const std::vector<unsigned char>& R) {
    constexpr size_t OUTPUT_KEY_LEN = 16; 

    unsigned char output[32]; 
    HMAC_CTX* ctx = HMAC_CTX_new();

    if (!ctx ||
        !HMAC_Init_ex(ctx, rk.data(), rk.size(), EVP_sha256(), nullptr) ||
        !HMAC_Update(ctx, R.data(), R.size()) ||                         
        !HMAC_Final(ctx, output, nullptr)) {
        if (ctx) HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC failed");
    }

    std::vector<unsigned char> AK(output, output + OUTPUT_KEY_LEN);          
    std::vector<unsigned char> MK(output + OUTPUT_KEY_LEN, output + 2 * OUTPUT_KEY_LEN); 

    HMAC_CTX_free(ctx);
    return {AK, MK}; 
}


std::pair<std::vector<unsigned char>, std::vector<unsigned char>> f3(
    const std::vector<unsigned char>& AK,
    const std::vector<unsigned char>& SUTI) {
    constexpr size_t OUTPUT_KEY_LEN = 16; 
    unsigned char output[32]; 
    HMAC_CTX* ctx = HMAC_CTX_new();

    if (!ctx ||
        !HMAC_Init_ex(ctx, AK.data(), AK.size(), EVP_sha256(), nullptr) || 
        !HMAC_Update(ctx, SUTI.data(), SUTI.size()) ||                   
        !HMAC_Final(ctx, output, nullptr)) {
        if (ctx) HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC failed");
    }

    std::vector<unsigned char> RK(output, output + OUTPUT_KEY_LEN);          
    std::vector<unsigned char> SK(output + OUTPUT_KEY_LEN, output + 2 * OUTPUT_KEY_LEN);
    HMAC_CTX_free(ctx);
    return {RK, SK}; 
}


std::vector<unsigned char> f1(const std::vector<unsigned char>& MK, const std::vector<unsigned char>& input) {
    unsigned char output[32];
    HMAC_CTX* ctx = HMAC_CTX_new();

    if (!ctx ||
        !HMAC_Init_ex(ctx, MK.data(), MK.size(), EVP_sha256(), nullptr) ||
        !HMAC_Update(ctx, input.data(), input.size()) ||
        !HMAC_Final(ctx, output, nullptr)) {
        if (ctx) HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC computation failed");
    }

    std::vector<unsigned char> MAC(output, output + 16);
    HMAC_CTX_free(ctx);
    return MAC;
}

int main() {

    try {

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

    
        // ------ Generate receiver's key pair
        EC_KEY* receiverKey = generateKeyPair();
        std::cout << "Receiver's public and private keys generated.\n";

        // Encapsulate key and get ck
        auto [C0, ck] = encapsulateKey(receiverKey);
        std::cout << "Encapsulated Key (C0, size " << C0.size() << "): " << toHex(C0) << "\n";
        std::cout << "Encapsulated Shared Key (ck): " << toHex(ck) << "\n";

        //Generating PGUP Message m0

        std::cout << "[NAS]    Generating PGUP Message m0." << "\n";
        std::cout << "[NAS]    Generating SUPI." << "\n";

        // ------ Generate random SUTI
        auto suti = generateSUTI();
        std::cout << "Generated SUPI: " << toHex(suti) << "\n";

        std::cout << "\033[1;32m" << "[NAS]    Generating SUPI Syccessfully." << "\033[0m" << "\n";


        unsigned char salt[SALT_LENGTH];  
        unsigned char hash[EVP_MAX_MD_SIZE]; 
        unsigned int hash_len = 0; 
        EVP_MD_CTX *mdctx = NULL; 

        ERR_load_crypto_strings();

        CHECK_ERROR(RAND_bytes(salt, SALT_LENGTH) > 0, "unable generate random salt");
        printf("Generated Salt:");
        for (int i = 0; i < SALT_LENGTH; i++) {
            printf("%02X", salt[i]);
        }
        printf("\n");


        // ------ Hash
        mdctx = EVP_MD_CTX_new();
        CHECK_ERROR(mdctx != NULL, "Unable Hash");

        CHECK_ERROR(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) > 0, "Init SHA-256 Failed");

        CHECK_ERROR(EVP_DigestUpdate(mdctx, salt, SALT_LENGTH) > 0, "Add Salt Failed");
        CHECK_ERROR(EVP_DigestUpdate(mdctx, suti.data(), suti.size()) > 0, "Add SUTI Failed");

        CHECK_ERROR(EVP_DigestFinal_ex(mdctx, hash, &hash_len) > 0, "Hash Failed");

        printf("Hash of SUTI: ");
        for (unsigned int i = 0; i < hash_len; i++) {
            printf("%02X", hash[i]);
        }
        printf("\n");


        // ------ Encryption
        auto encrypted_suti = encryptSUTI(suti, ck);
        std::cout << "Encrypted SUTI: " << toHex(encrypted_suti) << "\n";



        std::cout << "[NAS]    Generating data using PKW+." << "\n";
        std::cout << "\033[1;32m" << "[NAS]    Generating PGUP Message m0 Syccessfully." << "\033[0m" << "\n";


        // ------ PKW
        PPRF_AEAD_PKW pkw_UE(256, 196);

        std::vector<unsigned char> C0_c = C0; 
        std::vector<unsigned char> C1 = encrypted_suti;


        std::vector<unsigned char> AD(C0_c);
        AD.insert(AD.end(), C1.begin(), C1.end());


        int T = 8;

        std::vector<unsigned char> payload(hash, hash + hash_len);
        payload.insert(payload.end(), salt, salt + SALT_LENGTH);


        std::vector<unsigned char> C2 = pkw_UE.wrap(T, AD, payload);
        std::cout << "--------------------------" << std::endl;
        std::cout << "Tag (T): " << T << std::endl;
        std::cout << "Additional Data (AD = C0 ∥ C1): ";
        print_hex(AD);
        std::cout << "Payload (SUTI* ∥ Δ): ";
        print_hex(payload);
        std::cout << "Ciphertext (C2): ";
        print_hex(C2);
        std::cout << "--------------------------" << std::endl;

        auto sk_new = pkw_UE.gensk(T);
        pkw_UE.Drv(sk_new, AD);
        std::cout << "Drv complete, generate rk successful." << std::endl;

        T = 88;
        pkw_UE.punc(T);
        std::cout << "Punc Successful, to tag T=" << T << " Gen new K*!" << std::endl;

        ciphertext SUCI = C2;

        // generating C2

        // ------ Decaps
        std::vector<unsigned char> ck_dec = decapsulateKey(receiverKey, C0);

        std::cout << "Decapsulated Shared Key (ck_dec): ";
        for (unsigned char byte : ck_dec) {
            printf("%02x", byte);
        }
        std::cout << "\n";

        // Verify
        if (ck == ck_dec) {
            std::cout << "Success: Encapsulated and Decapsulated keys match.\n";
        } else {
            std::cout << "Error: Encapsulated and Decapsulated keys do not match.\n";
        }

        // Decrypt the SUTI using ck
        auto decrypted_suti = decryptSUTI(encrypted_suti, ck);
        std::cout << "Decrypted SUTI: " << toHex(decrypted_suti) << "\n";

        // Verify if decryption matches the original SUTI
        if (suti == decrypted_suti) {
            std::cout << "Success: Decrypted SUTI matches the original.\n";
        } else {
            std::cout << "Error: Decrypted SUTI does not match the original.\n";
        }

        // ------ Drv

        PPRF_AEAD_PKW pkw_CN(256, 196);

        // auto sk_CN = pkw_CN.gensk(T);
        // pkw_CN.Drv(sk_CN, AD);

        SecureByteBuffer rk = pkw_CN.gensk(T); 
        pkw_CN.Drv(rk, AD);       
        std::cout << "Drv complete, generate rk successful." << std::endl;

        T = 8;

        std::vector<unsigned char> unwrapped_payload = pkw_CN.unwrap(T, AD, C2);
        std::cout << "unwrapped successfule, data:";
        print_hex(unwrapped_payload);

        if (unwrapped_payload == payload) {
            std::cout << "check pass" << std::endl;
        } else {
            std::cerr << "check failed" << std::endl;
        }

        pkw_CN.punc(T);
        std::cout << "pkw_CN punc successful, to tag T=" << T << " Gen New K*!" << std::endl;

        // Hash
        // ------ Hash
        mdctx = EVP_MD_CTX_new();
        CHECK_ERROR(mdctx != NULL, "Unable Hash");

        CHECK_ERROR(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) > 0, "Init SHA-256 failed");

        CHECK_ERROR(EVP_DigestUpdate(mdctx, salt, SALT_LENGTH) > 0, "add salt failed");
        CHECK_ERROR(EVP_DigestUpdate(mdctx, suti.data(), suti.size()) > 0, "add SUTI failed");

        CHECK_ERROR(EVP_DigestFinal_ex(mdctx, hash, &hash_len) > 0, "hash failed");

        printf("hash of SUTI with salt");
        for (unsigned int i = 0; i < hash_len; i++) {
            printf("%02X", hash[i]);
        }
        printf("\n");

        // ------ R5
        std::vector<unsigned char> R = generate_random_data(16);

        auto [AK, MK] = f5(std::vector<unsigned char>(rk.begin(), rk.end()), R);

        // Output AK and MK
        std::cout << "AK: ";
        print_hex(AK);
        std::cout << "MK: ";
        print_hex(MK);


        auto [RK, SK] = f3(AK, suti);
        std::cout << "RK: ";
        print_hex(RK);
        std::cout << "SK: ";
        print_hex(SK);

        // ------ Generate SQN and MAC
        std::vector<unsigned char> SQN = generate_random_data(6);
        std::vector<unsigned char> input(SQN);
        input.insert(input.end(), R.begin(), R.end());
        input.insert(input.end(), C2.begin(), C2.end());
        std::vector<unsigned char> MAC = f1(MK, input);

        std::cout << " (MAC) f1: ";

        print_hex(MAC);

        // Generate CONC
        std::vector<unsigned char> CONC(SQN.size());
        for (size_t i = 0; i < SQN.size(); ++i) {
            CONC[i] = SQN[i] ^ AK[i];
        }
        print_hex_new("CONC", CONC);

        // Generate AUTN
        std::vector<unsigned char> AUTN(CONC);
        AUTN.insert(AUTN.end(), MAC.begin(), MAC.end());
        print_hex_new("AUTN", AUTN);

        // AEAD Encryption
        // CryptoPP::SecByteBlock ck(16);
        CryptoPP::SecByteBlock nonce(12);

        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(ck.data(), ck.size(), MK.data(), MK.size(), nullptr, 0, nullptr, 0);

        print_hex_new("HKDF Input MK", MK);
        print_hex_new("Derived Encryption Key (ck)", std::vector<unsigned char>(ck.begin(), ck.end()));

        print_hex_new("Nonce Before Encryption", std::vector<unsigned char>(nonce.begin(), nonce.end()));

        print_hex_new("Original CONC", CONC);
        print_hex_new("Original AK", AK);


        std::string encrypted_data;
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(ck.data(), ck.size(), nonce.data(), nonce.size());

        CryptoPP::AuthenticatedEncryptionFilter ef(
            enc,
            new CryptoPP::StringSink(encrypted_data)
        );
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, reinterpret_cast<const byte*>(AD.data()), AD.size());
        ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte*>(AUTN.data()), AUTN.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        print_hex_new("R' (Encrypted Data)", std::vector<unsigned char>(encrypted_data.begin(), encrypted_data.end()));

        // AEAD Decryption
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(ck.data(), ck.size(), nonce.data(), nonce.size());

        std::string decrypted_data;
        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(decrypted_data),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION
        );
        df.ChannelPut(CryptoPP::AAD_CHANNEL, reinterpret_cast<const byte*>(AD.data()), AD.size());
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte*>(encrypted_data.data()), encrypted_data.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        std::vector<unsigned char> decrypted_autn(decrypted_data.begin(), decrypted_data.end());
        print_hex_new("Decrypted AUTN", decrypted_autn);

        // Extract xCONC and xMAC
        std::vector<unsigned char> xCONC(decrypted_autn.begin(), decrypted_autn.begin() + CONC.size());
        std::vector<unsigned char> xMAC(decrypted_autn.begin() + CONC.size(), decrypted_autn.end());

        print_hex_new("Decrypted xCONC", xCONC);
        print_hex_new("Decrypted xMAC", xMAC);

        


        // Recompute SQN and MAC
        auto [new_AK, new_MK] = f5(std::vector<unsigned char>(rk.begin(), rk.end()), R);
        std::vector<unsigned char> recomputed_SQN(SQN.size());
        for (size_t i = 0; i < xCONC.size(); ++i) {
            recomputed_SQN[i] = xCONC[i] ^ new_AK[i];
        }
        print_hex_new("Recomputed SQN", recomputed_SQN);

        std::vector<unsigned char> recomputed_input(recomputed_SQN);
        recomputed_input.insert(recomputed_input.end(), R.begin(), R.end());
        recomputed_input.insert(recomputed_input.end(), C2.begin(), C2.end());
        std::vector<unsigned char> recomputed_MAC = f1(new_MK, recomputed_input);

        print_hex_new("Recomputed MAC", recomputed_MAC);

        print_hex_new("Decrypted xCONC", xCONC);
        print_hex_new("Recomputed SQN", recomputed_SQN);
        print_hex_new("Recomputed AK", new_AK);

        // Verify MAC
        if (recomputed_MAC == xMAC) {
            std::cout << "MAC verification successful!" << std::endl;
        } else {
            std::cout << "MAC verification failed!" << std::endl;
        }

        // Check SQN condition
        if (!std::lexicographical_compare(SQN.begin(), SQN.end(), recomputed_SQN.begin(), recomputed_SQN.end())) {
            std::cout << "SQN condition satisfied!" << std::endl;
        } else {
            std::cout << "SQN condition failed!" << std::endl;
        }

        EC_KEY_free(receiverKey);
        EVP_cleanup();
        ERR_free_strings();

    } catch (const PuncturableKeyWrappingException& e) {
    std::cerr << "PuncturableKeyWrappingException: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception caught." << std::endl;
    }

    return 0;

}

