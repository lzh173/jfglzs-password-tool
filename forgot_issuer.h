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

std::string reverse_rate_issuer(const std::string& input);
std::string base64_decode(const std::string& input);

std::string decrypt_forgot_issuer(const std::string& encrypted_str) {
    // 尝试补全缺失的首尾字符（各1个）
    for (int first_char = 32; first_char < 127; ++first_char) {
        for (int last_char = 32; last_char < 127; ++last_char) {
            std::string repaired_str;
            repaired_str += static_cast<char>(first_char);
            repaired_str += encrypted_str;
            repaired_str += static_cast<char>(last_char);

            try {
                // 逆向 RateIssuer
                std::string base64_str = reverse_rate_issuer(repaired_str);

                // DES 解密准备
                std::string key = "C:\\WINDO";  // 取前8字节
                std::string iv = ":\\WINDOW";   // 取后8字节

                // 使用EVP接口解密
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) continue;

                if (1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL,
                    reinterpret_cast<const unsigned char*>(key.data()),
                    reinterpret_cast<const unsigned char*>(iv.data()))) {
                    EVP_CIPHER_CTX_free(ctx);
                    continue;
                }

                // Base64解码
                std::string ciphertext = base64_decode(base64_str);
                std::vector<unsigned char> decrypted(ciphertext.size() + 8);
                int out_len = 0;

                if (1 != EVP_DecryptUpdate(ctx, decrypted.data(), &out_len,
                    reinterpret_cast<const unsigned char*>(ciphertext.data()),
                    ciphertext.size())) {
                    EVP_CIPHER_CTX_free(ctx);
                    continue;
                }

                int final_len = 0;
                if (1 != EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len)) {
                    EVP_CIPHER_CTX_free(ctx);
                    continue;
                }

                EVP_CIPHER_CTX_free(ctx);

                // 去除填充
                size_t total_len = out_len + final_len;
                if (total_len == 0) continue;

                unsigned char pad_len = decrypted[total_len - 1];
                if (pad_len > 0 && pad_len <= 8) {
                    std::string result(decrypted.begin(), decrypted.begin() + total_len - pad_len);
                    return result;
                }
            }
            catch (...) {
                continue;  // 当前组合失败，尝试下一个
            }
        }
    }

    throw std::runtime_error("e1");
}

// 辅助函数实现
std::string reverse_rate_issuer(const std::string& input) {
    std::string result;
    for (char c : input) {
        result += static_cast<char>(c + 10);  // 逆向操作
    }
    return result;
}

std::string base64_decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), input.size());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::vector<char> output(input.size());
    int len = BIO_read(b64, output.data(), input.size());
    BIO_free_all(b64);

    if (len <= 0) {
        throw std::runtime_error("Base64 decode failed");
    }

    return std::string(output.data(), len);
}
