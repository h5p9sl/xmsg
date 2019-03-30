#include "keychain.hpp"

#include <string>
#include <iostream>
#include <fstream>
#include <limits>
#include <cstring>

constexpr char keyfile[] = "./xmsgkey.txt";

Keychain::Keychain() :
    currentKeyIndex(0)
{
    this->getKeyNames();

    while (this->keyNames.size() > 1) {
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
        
        if (choice >= 0 && choice <= this->keyNames.size() - 1) {
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
            std::string keyStr = line.substr(15);
            for (unsigned j = 0; j < keyStr.length() - 15; j++) {
                key.at(j) = keyStr[j];
            }
            break;
        }
        i++;
    }

    file.close();
    return key;
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

void Keychain::getKeyNames()
{
    std::ifstream file(keyfile);
    std::string line;

    if (!file.is_open()) {
        printf("Could not open %s... Does it exist?\n", keyfile);
        file.close();
        exit(0);
        return;
    }

    while (std::getline(file, line)) {
        this->keyNames.push_back(line.substr(0, 15));
    }

    file.close();
}
