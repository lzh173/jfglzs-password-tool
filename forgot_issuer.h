#pragma once
#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <openssl/des.h>
#include <openssl/buffer.h>
#include "base64.h"



inline std::string rate_issuer(const std::string& input) {
    std::string result;
    for (char c : input) result += static_cast<char>(c - 10);
    return result;
}


inline std::string forgot_issuer(const std::string& input) {
    std::string key = "C:\\WINDO";
    std::string iv = ":\\WINDOW";
    // PKCS7 padding
    size_t pad_len = 8 - (input.size() % 8);
    std::string padded = input + std::string(pad_len, static_cast<char>(pad_len));

    DES_cblock key_block, iv_block;
    memcpy(key_block, key.data(), 8);
    memcpy(iv_block, iv.data(), 8);
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key_block, &schedule);

    std::vector<unsigned char> encrypted(padded.size());
    DES_cblock iv_copy;
    memcpy(iv_copy, iv_block, 8); // 每次都要拷贝

    DES_ncbc_encrypt((const unsigned char*)padded.data(), encrypted.data(), (long)padded.size(), &schedule, &iv_copy, DES_ENCRYPT);

    std::string base64_str = base64_encode(encrypted);
    return rate_issuer(base64_str);
}

// 逆向字符位移
inline std::string reverse_rate_issuer(const std::string& encrypted_str) {
    std::string result;
    for (char c : encrypted_str) {
        result += static_cast<char>(c + 10);
    }
    return result;
}

// base64解码
inline std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO* bio, * b64;
    int maxlen = encoded.length() * 3 / 4 + 1;
    std::vector<unsigned char> buffer(maxlen);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    bio = BIO_push(b64, bio);
    int decoded_size = BIO_read(bio, buffer.data(), encoded.length());
    if (decoded_size <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("base64 decode error");
    }
    buffer.resize(decoded_size);
    BIO_free_all(bio);
    return buffer;
}

// DES CBC解密
inline std::vector<unsigned char> des_cbc_decrypt(
    const std::vector<unsigned char>& ciphertext,
    const unsigned char* key,
    const unsigned char* iv)
{
    DES_cblock keyBlock, ivec;
    memcpy(keyBlock, key, 8);
    memcpy(ivec, iv, 8);

    DES_key_schedule schedule;
    DES_set_key_unchecked(&keyBlock, &schedule);

    std::vector<unsigned char> plaintext(ciphertext.size());
    DES_ncbc_encrypt(ciphertext.data(), plaintext.data(), ciphertext.size(), &schedule, &ivec, DES_DECRYPT);
    return plaintext;
}

// 去除填充
inline std::string remove_padding(const std::vector<unsigned char>& decrypted) {
    if (decrypted.empty()) throw std::runtime_error("empty decrypted");
    unsigned char pad_len = decrypted.back();
    if (pad_len > 0 && pad_len <= 8 && decrypted.size() >= pad_len) {
        return std::string(decrypted.begin(), decrypted.end() - pad_len);
    }
    return std::string(decrypted.begin(), decrypted.end());
}

// 解密主函数
inline std::string decrypt_forgot_issuer(const std::string& encrypted_str) {
    std::vector<char> possible_chars;
    for (int i = 32; i < 127; ++i) possible_chars.push_back(static_cast<char>(i));

    for (char first_char : possible_chars) {
        for (char last_char : possible_chars) {
            std::string repaired_str = first_char + encrypted_str + last_char;
            try {
                // 逆向RateIssuer
                std::string base64_str = reverse_rate_issuer(repaired_str);
                // base64解码
                std::vector<unsigned char> decoded = base64_decode(base64_str);
                // DES CBC解密
                unsigned char s[8] = { 'C',':','\\','W','I','N','D','O' };
                unsigned char s2[8] = { ':','\\','W','I','N','D','O','W' };
                std::vector<unsigned char> decrypted = des_cbc_decrypt(decoded, s, s2);
                // 去除填充
                std::string result = remove_padding(decrypted);

                // 可选：判断是否为可打印字符串
                bool printable = true;
                for (char ch : result) {
                    if (ch < 32 || ch > 126) { printable = false; break; }
                }
                if (printable) return result; // 找到明文直接返回

            }
            catch (...) {
                continue;
            }
        }
    }
    throw std::runtime_error("e1");
}