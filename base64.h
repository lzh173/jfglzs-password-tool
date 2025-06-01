#pragma once
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string>
#include <vector>

inline std::string base64_encode(const std::vector<unsigned char>& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // ����ӻ��з�
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // д������
    BIO_write(bio, input.data(), static_cast<int>(input.size()));
    BIO_flush(bio);

    // ��ȡ���
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);

    // �ͷ���Դ
    BIO_free_all(bio);

    return encoded;
}