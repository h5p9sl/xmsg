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

#include "keychain.hpp"

static bool _debug = false;
static Keychain* keychain = nullptr;

void help(char* argv[]) {
    printf("Usage: %s [optional flags]\n", argv[0]);
    puts("xmsg is a cryptography program that aims to create strong encrypted messages for two or more people.");
    puts("-h    --help      : display this help message.");
    puts("-d    --debug     : enable debug messages.");
    puts("      --createkey : create encryption key.");
    puts("      --deletekey : delete encryption key.");
}

std::string getInput() {
    std::string line;
    std::cout << '(' << keychain->getKeyIndex() << ") xmsg > " << std::flush;
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
    uint16_t messageLength;
    uint8_t IV[AES_BLOCKLEN];
};

void InitializeAES(AES_ctx* ctx) {
    // Get key from file
    if (_debug) puts("Loading encyption key into memory");
    std::array<uint8_t, AES_KEYLEN> key = keychain->getKey();
    // Initialize AES
    if (_debug) puts("Creating roundkey and randomized IV...");
    AES_init_ctx(ctx, key.data());
    randomizeIV(ctx);
}

// This function essentially just prevents from memory dumps,
// by removing sensitive data from memory as soon as we're done using it
void DestroyAES(AES_ctx* ctx) {
    memset(ctx, 0, sizeof(AES_ctx));
}

void xmsg() {
    // Create AES context
    AES_ctx* ctx = new AES_ctx;
    // Create Keychain instance
    keychain = new Keychain();

    while (true) {
        puts("Type in a message.");
        std::string msg = getInput();
        puts("Encrypt or Decrypt? (e/d)");
        std::string option = getInput();
        if (option.compare("e") == 0) {
            puts("Encrypting data...");

            if (_debug) puts("Initializing AES context...");
            InitializeAES(ctx);

            size_t msgLen = msg.length();
            while (msgLen % 16 != 0) msgLen++;
            uint8_t* buf = new uint8_t[msgLen + sizeof(AESMetadata)];

            memset(buf + msg.length() + sizeof(AESMetadata), msgLen - msg.length(), msgLen - msg.length());
            memcpy(buf + sizeof(AESMetadata), msg.data(), msg.length());

            AESMetadata* md = (AESMetadata*)buf;
            md->messageLength = msg.length();
            memcpy(md->IV, ctx->Iv, AES_BLOCKLEN);

            if (_debug) puts("Encrypting buffer...");
            AES_CBC_encrypt_buffer(ctx, sizeof(AESMetadata) + buf, msgLen);
            
            DestroyAES(ctx);

            std::cout << base64_encode(buf, msgLen + sizeof(AESMetadata)) << std::endl;

            delete buf;
        }
        else if (option.compare("d") == 0) {
            puts("Decrypting data...");
            std::string data = base64_decode(msg);
            uint8_t* buf = (uint8_t*)data.data();
            
            if (_debug) puts("Initializing AES context...");
            InitializeAES(ctx);

            // Extract metadata
            AESMetadata* md = (AESMetadata*)data.data();
            // Set IV
            AES_ctx_set_iv(ctx, md->IV);

            if (_debug) {
                std::cout << "AES->RoundKey == { ";
                for (int i = 0; i < AES_keyExpSize; i++) {
                    std::cout << std::hex << (int)ctx->RoundKey[i] << ", ";
                }
                std::cout << "}\n";
            }

            if (_debug) puts("Decrypting buffer...");
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

void createkey()
{
    std::string keyName, choice;
    puts("What do you want to call the key? (MAX 16 CHARS)");
    std::cout << "Name: " << std::flush;
    std::getline(std::cin, keyName);
    keyName.resize(16, '\0');
    while (true) {
        puts("Do you want to randomize the key? (y/n)");
        std::cout << '\"' << keyName << "\": ";
        std::getline(std::cin, choice);
        if (choice.compare("y") == 0) {
            std::array<uint8_t, AES_KEYLEN> key;
            key.fill(0);

            constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=`~\\\"\';:?/>.<,[]{}|";

        #ifdef __linux__
            ssize_t n = getrandom(key.data(), AES_KEYLEN, 0);
            if (n == -1) {
                perror("getrandom");
                return;
            }
        #elif defined(_WIN32)
            BCRYPT_ALG_HANDLE hAlg;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, NULL);
            NTSTATUS status = BCryptGenRandom(hAlg, key.data(), AES_KEYLEN, NULL);
            if (status != 0l) {
                puts("BCryptGenRandom failed!");
                printf("GetLastError() = %i\n", GetLastError());
                return;
            }
        #endif

            std::cout << "Generated random key: ";
            for (int i = 0; i < AES_KEYLEN; i++) {
                key.at(i) = alphabet[key[i] * strlen(alphabet) / UINT8_MAX];
                std::cout << (char)key[i];
            }
            std::cout << '\n';

            keychain->createKey(keyName, key);
            puts("Randomized key generated.");
            break;
        } else if (choice.compare("n") == 0) {
            puts("Please enter what you want the key to be (MAX 32 CHARS)");
            std::cout << '\"' << keyName << "\": ";
            std::array<uint8_t, AES_KEYLEN> key;
            key.fill(0);
            std::string input;
            std::getline(std::cin, input);

            for (unsigned i = 0; i < input.length(); i++) {
                key.at(i) = input[i];
            }

            keychain->createKey(keyName, key);
            break;
        }
    }
        }

int main(int argc, char* argv[]) {

    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            help(argv);
            return 0;
        }
        else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--debug") == 0) {
            _debug = true;
        }
        else if (strcmp(argv[1], "--createkey") == 0) {
            createkey();
            return 0;
        }
        else {
            printf("Error: Unrecognized argument \"%s\".\n", argv[1]);
            puts("Launch this program with the \"--help\" flag to see a list of arguments.");
            return 0;
        }
    }

    puts("Tip: Launch this program with the \"--help\" flag to see a list of arguments.");
    xmsg();

    return 0;
}
