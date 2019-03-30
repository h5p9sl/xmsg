// Acknowledgments:
//  https://github.com/ReneNyffenegger/cpp-base64
//  https://github.com/kokke/tiny-AES-c

#include <cstring>
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>

#ifdef __linux__
#include <sys/random.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#endif

#ifdef __linux__
#include "aes.h"
#else
#include "aes.hpp"
#endif
#include "base64.hpp"

static bool _debug = false;

void help(char* argv[]) {
    printf("Usage: %s [optional flags]\n", argv[0]);
    puts("xmsg is a cryptography program that aims to create strong encrypted messages for two or more people.");
    puts("-h    --help    : display this help message.");
    puts("-d    --debug   : enable debug messages.");
}

std::string getInput() {
    std::string line;
    std::cout << "xmsg$ " << std::flush;
    std::getline(std::cin, line);
    return line;
}

void randomizeIV(AES_ctx* ctx) {
    // Generate random IV
    uint8_t iv[AES_BLOCKLEN];
#ifdef __linux__
    ssize_t n = getrandom(iv, AES_BLOCKLEN, 0);
    if (n == -1) {
        perror("getrandom");
        return;
    }
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, NULL);
    NTSTATUS status = BCryptGenRandom(hAlg, iv, AES_BLOCKLEN, NULL);
    if (status != 0l) {
        puts("BCryptGenRandom failed!");
        printf("GetLastError() = %i\n", GetLastError());
        return;
    }
#endif

    if (_debug) {
        printf("iv = { ");
        for (int i = 0; i < AES_BLOCKLEN; i++) printf("%i, ", iv[i]);
        printf("}\n");
    }

    AES_ctx_set_iv(ctx, iv);
}

// Metadata that comes BEFORE the encrypted data
struct AESMetadata
{
    int messageLength;
    uint8_t IV[AES_BLOCKLEN];
};

void InitializeAES(AES_ctx* ctx) {
    // Get key from file
    std::ifstream keyfile("./xmsgkey.txt");
    uint8_t* key = new uint8_t[AES_KEYLEN];
    memset(key, 0, AES_KEYLEN);

    if (keyfile.is_open()) {
        keyfile.read((char*)key, AES_KEYLEN);
    } else {
        puts("Could not open ./xmsgkey.txt... Does it exist?");
        keyfile.close();
        return;
    }
    keyfile.close();

    // Initialize AES
    AES_init_ctx(ctx, key);
    randomizeIV(ctx);
    memset(key, 0, AES_KEYLEN);
    delete key;
}

// This function essentially just prevents from memory dumps,
// by removing sensitive data from memory as soon as we're done using it
void DestroyAES(AES_ctx* ctx) {
    memset(ctx, 0, sizeof(AES_ctx));
}

void xmsg() {
    // Create AES context
    AES_ctx* ctx = new AES_ctx;

    while (true) {
        puts("Type in a message.");
        std::string msg = getInput();
        puts("Encrypt or Decrypt? (e/d)");
        std::string option = getInput();
        if (option.compare("e") == 0) {
            puts("Encrypting data...");

            InitializeAES(ctx);

            size_t msgLen = msg.length();
            while (msgLen % 16 != 0) msgLen++;
            uint8_t* buf = new uint8_t[msgLen + sizeof(AESMetadata)];

            memset(buf + msg.length() + sizeof(AESMetadata), msgLen - msg.length(), msgLen - msg.length());
            memcpy(buf + sizeof(AESMetadata), msg.data(), msg.length());

            AESMetadata* md = (AESMetadata*)buf;
            md->messageLength = msg.length();
            memcpy(md->IV, ctx->Iv, AES_BLOCKLEN);

            AES_CBC_encrypt_buffer(ctx, sizeof(AESMetadata) + buf, msgLen);
            
            DestroyAES(ctx);

            std::cout << base64_encode(buf, msgLen + sizeof(AESMetadata)) << std::endl;

            delete buf;
        }
        else if (option.compare("d") == 0) {
            puts("Decrypting data...");
            std::string data = base64_decode(msg);
            uint8_t* buf = (uint8_t*)data.data();
            
            InitializeAES(ctx);

            // Extract metadata
            AESMetadata* md = (AESMetadata*)data.data();
            // Set IV
            AES_ctx_set_iv(ctx, md->IV);

            AES_CBC_decrypt_buffer(ctx, buf + sizeof(AESMetadata), data.size() - sizeof(AESMetadata));

            DestroyAES(ctx);

            std::string finalMessage = data.substr(sizeof(AESMetadata), md->messageLength);
            std::cout << '\"' << finalMessage << '\"' << std::endl;
        }
        else {
            puts("Invalid option.");
        }
    }

    delete ctx;
}

int main(int argc, char* argv[]) {
    if (argc == 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            help(argv);
            return 0;
        }
        else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--debug") == 0) {
            _debug = true;
        }
        else {
            printf("Error: Unrecognized argument \"%s\".\n", argv[1]);
            help(argv);
        }
    }

    xmsg();

    return 0;
}
