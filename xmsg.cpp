#include "xmsg.hpp"

#include <cstring>
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <limits>

#ifdef __linux__
#include <sys/random.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#endif

// Compiler hack
#ifdef __linux__
#include "aes.h"
#else
#include "aes.hpp"
#endif
#include "base64.hpp"
#include "argparser.hpp"

static bool _debugMode = false;
static bool _encrypt = false;

void encryptMessage(AES_ctx* ctx, std::string msg);
void decryptMessage(AES_ctx* ctx, std::string msg);
void inline debugPrint(const char* output);

// Metadata that comes BEFORE the encrypted data
struct AESMetadata {
    uint16_t messageLength;
    uint8_t IV[AES_BLOCKLEN];
};

void debugPrint(const char* output) {
    if (_debugMode == true) {
        puts(output);
    }
}

void encryptMessage(AES_ctx* ctx, std::string msg) {
    debugPrint("Encrypting data...");

    size_t msgLen = msg.length();
    while (msgLen % 16 != 0) msgLen++;
    uint8_t* buf = new uint8_t[msgLen + sizeof(AESMetadata)];

    // Generate random bytes to fill in the extra space at the end of the message.
    {
        std::vector<uint8_t> randomBytes = Application::generateRandomBytes(msgLen - msg.length());
        memcpy(buf + sizeof(AESMetadata) + msg.length(), randomBytes.data(), randomBytes.size());
        memcpy(buf + sizeof(AESMetadata), msg.data(), msg.length());
    }

    AESMetadata* md = (AESMetadata*)buf;
    md->messageLength = msg.length();
    memcpy(md->IV, ctx->Iv, AES_BLOCKLEN);

    debugPrint("Encrypting buffer...");
    AES_CBC_encrypt_buffer(ctx, sizeof(AESMetadata) + buf, msgLen);

    std::cout << base64_encode(buf, msgLen + sizeof(AESMetadata)) << std::endl;

    delete buf;
}

void decryptMessage(AES_ctx* ctx, std::string msg) {
    debugPrint("Decrypting data...");
    std::string data = base64_decode(msg);
    uint8_t* buf = (uint8_t*)data.data();

    // Extract metadata
    AESMetadata* md = (AESMetadata*)data.data();
    // Set IV
    AES_ctx_set_iv(ctx, md->IV);

    debugPrint("Decrypting buffer...");
    AES_CBC_decrypt_buffer(ctx, buf + sizeof(AESMetadata), data.size() - sizeof(AESMetadata));

    std::string finalMessage = data.substr(sizeof(AESMetadata), md->messageLength);
    std::cout << finalMessage;
}

std::vector<uint8_t> Application::generateRandomBytes(const int count) {
    std::vector<uint8_t> result;
    result.resize(count);
#ifdef __linux__
    ssize_t n = getrandom(result.data(), count, 0);
    if (n == -1) {
        perror("getrandom");
        return result;
    }
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, 0, 0);
    NTSTATUS status = BCryptGenRandom(hAlg, result.data(), count, 0);
    if (status != 0l) {
        puts("BCryptGenRandom failed!");
        printf("GetLastError() = %li\n", GetLastError());
        return result;
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
#endif
    return result;
}

void Application::processArguments(const int argc, char** argv) {
    
    unsigned overflow_count = 0;
    char** overflow = new char*[argc];

    if (argc < 2) {
        printf("Insufficient number of arguments...\n");
        exit(1);
    }

    ARGPARSER_parseProgramArguments((int)argc - 1, &argv[1], overflow, sizeof(char*) * argc, &overflow_count);

    if (overflow_count > 0) {
        printf("Invalid arguments...\n");
        for (unsigned i = 0; i < overflow_count; i++) {
            printf("%i: %s\n", i, overflow[i]);
        }
        exit(1);
    }

    if (argparser_context.encrypt == false && argparser_context.decrypt == false) {
        printf("Must specify --encrypt or --decrypt...\n");
        exit(1);
    }

    _encrypt = argparser_context.encrypt;
    _debugMode = argparser_context.debug;
    this->key = argparser_context.key;
}

Application::Application(const int argc, char** argv) :
    key(-1)
{
    _debugMode = false;
    processArguments(argc, argv);
}

void Application::start() {
    // This function essentially just prevents from memory dumps,
    // by removing sensitive data from memory as soon as we're done using it
    auto DestroyAES = [](AES_ctx* ctx) -> void {
        memset(ctx, 0, sizeof(AES_ctx));
    };
    auto InitializeAES = [this](AES_ctx* ctx) -> void {
        auto RandomizeIV = [](AES_ctx* ctx) -> void {
            std::vector<uint8_t> iv = Application::generateRandomBytes(AES_BLOCKLEN);
            AES_ctx_set_iv(ctx, iv.data());
        };
        // Get key from file
        std::array<uint8_t, AES_KEYLEN> key = this->keychain->getKey();
        // Initialize AES
        AES_init_ctx(ctx, key.data());
        RandomizeIV(ctx);
    };

    // Create AES context
    AES_ctx* ctx = new AES_ctx;
    // Create Keychain instance
    this->keychain = std::make_unique<Keychain>(this->key);

    std::string data;
    debugPrint("Reading input until EOF is reached.");
    while (std::cin.good()) {
        char c;
        std::cin.get(c);
        data.push_back(c);
    };
    // Get rid of EOF char
    data.pop_back();

    InitializeAES(ctx);
    (_encrypt) ? encryptMessage(ctx, data) : decryptMessage(ctx, data);
    DestroyAES(ctx);

    delete ctx;
}

