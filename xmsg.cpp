#include "xmsg.hpp"

#include <cstring>
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <limits>

#ifdef __linux__
#include <sys/random.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#endif

// Compiler hack
#ifdef __linux__
#include "aes.h"
#else
#include "aes.hpp"
#endif
#include "base64.hpp"

static bool _debugMode = false;

void help(char** argv);
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

void help(char** argv) {
    printf("Usage: %s [optional flags]\n", argv[0]);
    puts("xmsg is a cryptography program that aims to create strong encrypted messages for two or more people.");
    puts("-h    --help      : display this help message.");
    puts("-v    --version   : display xmsg version.");
    puts("-d    --debug     : enable debug messages.");
    puts("      --createkey : create encryption key.");
    puts("      --deletekey : delete encryption key.");
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
    std::cout << '\"' << finalMessage << '\"' << std::endl;
}

std::string Application::getInput() {
    std::string line;
    std::cout << '(' << this->keychain->getKeyIndex() << ") xmsg > " << std::flush;
    std::getline(std::cin, line);
    return line;
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
    BCRPYT_ALG_HANDLE hAlg;
    BCrpytOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, NULL);
    NTSTATUS status = BCryptGenRandom(hAlg, result.data(), count, NULL);
    if (status != 0l) {
        puts("BCryptGenRandom failed!");
        printf("GetLastError() = %i\n", GetLastError());
        return result;
    }
#endif
    return result;
}

void Application::processArguments(const int argc, char** argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            help(argv);
            exit(0);
        }
        else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("xmsg version %.1f\n", _xmsg_version);
            exit(0);
        }
        else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--debug") == 0) {
            _debugMode = true;
        }
        else if (strcmp(argv[1], "--createkey") == 0) {
            Keychain::createKey();
            exit(0);
        }
        else if (strcmp(argv[1], "--deletekey") == 0) {
            Keychain* keychain = new Keychain(false);
            keychain->deleteKey();
            delete keychain;
            exit(0);
        }
        else {
            printf("Error: Unrecognized argument \"%s\".\n", argv[1]);
            puts("Launch this program with the \"--help\" flag to see a list of arguments.");
            exit(0);
        }
    }
}

Application::Application(const int argc, char** argv)
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
    this->keychain = std::make_unique<Keychain>();

    // Application main loop
    while (true) {
        puts("Type in a message.");
        std::string msg = this->getInput();
        puts("Encrypt or Decrypt? (e/d)");
        std::string option = this->getInput();

        if (option.compare("e") == 0) {
            InitializeAES(ctx);
            encryptMessage(ctx, msg);
            DestroyAES(ctx);
        }
        else if (option.compare("d") == 0) {
            InitializeAES(ctx);
            decryptMessage(ctx, msg);
            DestroyAES(ctx);
        }
        else {
            puts("Invalid option.");
        }
    }

    delete ctx;
}

