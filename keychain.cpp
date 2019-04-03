#include "keychain.hpp"

#include <string>
#include <iostream>
#include <fstream>
#include <limits>
#include <cstring>
#include <algorithm>

#include "xmsg.hpp"

constexpr char keyfile[] = "./xmsgkey.txt";

Keychain::Keychain(const bool promptUser) :
    currentKeyIndex(0)
{
    this->loadKeyNames();

    while (promptUser && this->keyNames.size() > 1) {
        puts("Which encryption key do you want to use?");
        for (unsigned i = 0; i < this->keyNames.size(); i++) {
            printf("[%i]: \"%s\"\n", i, this->keyNames.at(i).c_str());
        }

        unsigned choice;
        std::cout << "xmsg > " << std::flush;
        std::cin >> choice;
        // Clear the input stream
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        if (choice <= this->keyNames.size() - 1) {
            this->currentKeyIndex = choice;
            break;
        } else {
            puts("Invalid option.");
        }
    }
}

std::array<uint8_t, AES_KEYLEN> Keychain::getKey()
{
    std::ifstream file(keyfile);
    std::string line;
    std::array<uint8_t, AES_KEYLEN> key;
    key.fill(0);

    if (!file.is_open()) {
        printf("Could not open %s... Does it exist?\n", keyfile);
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
        for (int i = 0; i < keyNames.size(); i++) {
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
    std::cout << "Creating a key named " << keyName << "...\n";
    std::cout << "Key data: ";
    for (int i = 0; i < AES_KEYLEN; i++) {
        std::cout << key[i];
    }
    std::cout << '\n';

    std::ofstream file(keyfile, std::ios::app | std::ios::out);
    if (!file.is_open()) {
        printf("Could not open %s for writing...\n", keyfile);
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
    std::ifstream file(keyfile);
    std::string line;

    if (!file.is_open()) {
        printf("Could not open %s... Does it exist?\n", keyfile);
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

