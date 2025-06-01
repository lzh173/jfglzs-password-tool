#include <iostream>
#include <cstring>
#include <openssl/buffer.h>
#include "forgot_issuer.h"

void print_help(){
    std::cout << "Usage: crypto_tool [OPTION]...\n"
        << "  -e, --enc STRING    Encrypt the given string\n"
        << "  -d, --dec STRING    Decrypt the given string\n"
        << "  -h, --help          Display this help and exit\n";
}

int main(int argc, char* argv[]) {
    std::string enc_str, dec_str;
    bool do_encrypt = false, do_decrypt = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--enc") == 0 || strcmp(argv[i], "-e") == 0) {
            if (i + 1 < argc) { enc_str = argv[++i]; do_encrypt = true; }
        }
        else if (strcmp(argv[i], "--dec") == 0 || strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) { dec_str = argv[++i]; do_decrypt = true; }
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help(); return 0;
        }
    }
    if (do_encrypt && do_decrypt) {
        std::cerr << "Error: Cannot specify both encryption and decryption.\n";
        return 1;
    }
    if (!do_encrypt && !do_decrypt) {
        std::cerr << "Error: No operation specified.\n";
        print_help();
        return 1;
    }
    try {
        if (do_encrypt) std::cout << forgot_issuer(enc_str) << std::endl;
        else if (do_decrypt) std::cout << decrypt_forgot_issuer(dec_str) << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}