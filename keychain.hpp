#ifndef _KEYCHAIN_HPP_
#define _KEYCHAIN_HPP_

#include <vector>
#include <array>

#include "aes.h"

// Class that manages the xmsg encryption key file
class Keychain
{
private:
    int currentKeyIndex;
    std::vector<std::string> keyNames;
public:
    int getKeyIndex() const { return this->currentKeyIndex; }
    std::vector<std::string> getKeyNames() { this->loadKeyNames(); return this->keyNames; }
public:
    Keychain(const int keyid);
    std::array<uint8_t, AES_KEYLEN> getKey();
    static void createKey();
    void deleteKey();
    static void createKey(std::string keyName, std::array<uint8_t, AES_KEYLEN> key);
private:
    void loadKeyNames();
};

#endif

