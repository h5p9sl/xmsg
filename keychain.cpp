#include "keychain.hpp"

#include <string>
#include <iostream>
#include <fstream>
#include <limits>
#include <cstring>
#include <algorithm>
#include <cstdio>

#include "xmsg.hpp"
#include "config.hpp"

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#elif defined(_WIN32)
#endif

Keychain::Keychain(const int keyid) :
    currentKeyIndex(keyid)
{
    this->loadKeyNames();
    // Invalid key was selected.
    if (keyid < 0 || (unsigned)keyid >= this->keyNames.size()) {
        puts("Which encryption key do you want to use?");
        for (unsigned i = 0; i < this->keyNames.size(); i++) {
            printf("[%i]: \"%s\"\n", i, this->keyNames.at(i).c_str());
        }
        exit(0);
    }
}

#ifdef __linux__
int mkdir_parents(const char* dir, const mode_t mode) {
    char* buf;
    int* sep;
    unsigned dc, i;

    dc = 0;
    sep = NULL;
    // Find all '/' characters in string
    // and store their positions in sep
    for (i = 0; i < strlen(dir); i++) {
        if (dir[i] == '/') {
            sep = (int*)realloc(sep, sizeof(int*) * ++dc);
            sep[dc - 1] = i;
        }
    }

    buf = (char*)malloc(strlen(dir) + 1);
    memset(buf, 0, strlen(dir) + 1);
    // Iterate through directories and create
    // non existing ones
    for (i = 1; i < dc; i++) {
        strncpy(buf, dir, sep[i] + 1);
        mkdir(buf, mode);
    }

    free(buf);
    return 0;
}
#endif

void Keychain::createKeyFile() {
    bool exists;

    exists = false;
#ifdef __linux__
    struct stat s;
    if (stat(KEYFILE_PATH, &s) == 0) {
        exists = (bool)S_ISREG(s.st_mode);
        printf("exists = %i\n", (int)exists);
    }

    if (!exists) {
        mkdir_parents(KEYFILE_PATH, 511);
    }
#elif defined(_WIN32)
    // TODO: Write WIN32 code here
#endif
}

std::array<uint8_t, AES_KEYLEN> Keychain::getKey()
{
    std::ifstream file(KEYFILE_PATH);
    std::string line;
    std::array<uint8_t, AES_KEYLEN> key;
    key.fill(0);

    if (!file.is_open()) {
        printf("Could not open %s... Does it exist?\n", KEYFILE_PATH);
        file.close();
        exit(0);
        return key;
    }

    int i = 0;
    while (std::getline(file, line, '\n')) {
        if (i == this->currentKeyIndex) {
            std::string keyStr = line.substr(16);
            for (unsigned j = 0; j < keyStr.length(); j++) {
                key.at(j) = keyStr[j];
            }
            break;
        }
        i++;
    }

    file.close();
    return key;
}

void Keychain::createKey() {
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
            {
                std::vector<uint8_t> keyVector = Application::generateRandomBytes(AES_KEYLEN);
                std::copy_n(keyVector.begin(), AES_KEYLEN, key.begin());
            }

            std::cout << "Generated random key: ";
            for (int i = 0; i < AES_KEYLEN; i++) {
                key.at(i) = alphabet[key[i] * strlen(alphabet) / UINT8_MAX];
                std::cout << (char)key[i];
            }
            std::cout << '\n';

            Keychain::createKey(keyName, key);
            puts("Randomized key generated.");
            break;
        } else if (choice.compare("n") == 0) {
            puts("Please enter what you want the key to be (MAX 32 CHARS)");
            std::cout << '\"' << keyName << "\": ";
            std::array<uint8_t, AES_KEYLEN> key;
            std::string input;
            std::getline(std::cin, input);
            input.resize(32, '\0');

            for (unsigned i = 0; i < input.length(); i++) {
                key.at(i) = input[i];
            }

            Keychain::createKey(keyName, key);
            break;
        }
    }
}

void Keychain::deleteKey() {
    while (true) {
        std::vector<std::string> keyNames = this->getKeyNames();
        for (unsigned i = 0; i < keyNames.size(); i++) {
            printf("[%i]: \"%s\"\n", i, keyNames.at(i).c_str());
        }
        puts("Which key would you like to delete?");

        unsigned choice;
        std::cout << "xmsg > " << std::flush;
        std::cin >> choice;
        // Clear the input stream
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice <= keyNames.size() - 1) {
            if (std::rename("xmsgkey.txt", "xmsgkey.bak") == 0) {
                std::ifstream in("xmsgkey.bak");
                std::ofstream out("xmsgkey.txt");
                if (in.is_open() && out.is_open()) {
                    if (keyNames.size() == 1) {
                        out.clear();
                        out.close();
                        in.close();
                    }
                    std::string line;
                    unsigned int i = 0;
                    while (std::getline(in, line)) {
                        if (i != choice) {
                            out << line;
                            out.put('\n');
                        }
                        i++;
                    }
                    in.close();
                    out.close();
                } else {
                    std::cout << "Could not open files...\n";
                }
            } else {
                perror("rename");
                return;
            }
        } else {
            puts("Invalid option.");
        }
    }
}

void Keychain::createKey(std::string keyName, std::array<uint8_t, AES_KEYLEN> key)
{
    // Checks if the key file exists, and creates one if it doesn't
    Keychain::createKeyFile();

    std::cout << "Creating a key named " << keyName << "...\n";
    std::cout << "Key data: ";
    for (int i = 0; i < AES_KEYLEN; i++) {
        std::cout << key[i];
    }
    std::cout << '\n';

    std::ofstream file(KEYFILE_PATH, std::ios::app | std::ios::out);
    if (!file.is_open()) {
        printf("Could not open %s for writing...\n", KEYFILE_PATH);
        file.close();
        return;
    }

    struct KeyData_t
    {
        char name[16];
        char key[32];
    } keydata;

    memset(&keydata, 0,  sizeof(KeyData_t));
    memcpy(keydata.name, keyName.data(), keyName.length());
    memcpy(keydata.key,  key.data(),     AES_KEYLEN);

    file.write((const char*)&keydata, sizeof(KeyData_t));
    file.put('\n');

    file.close();
}

void Keychain::loadKeyNames()
{
    std::ifstream file(KEYFILE_PATH);
    std::string line;

    if (!file.is_open()) {
        printf("Could not open \"%s\"... Does it exist?\n", KEYFILE_PATH);
        file.close();
        exit(0);
        return;
    }

    this->keyNames.clear();
    while (std::getline(file, line)) {
        this->keyNames.push_back(line.substr(0, 15));
    }

    file.close();
}

