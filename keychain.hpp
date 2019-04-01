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
    Keychain(const bool promptUser = true);
    int getKeyIndex() const { return this->currentKeyIndex; }
    std::array<uint8_t, AES_KEYLEN> getKey();
    static void createKey(std::string keyName, std::array<uint8_t, AES_KEYLEN> key);
    std::vector<std::string> getKeyNames() { this->loadKeyNames(); return this->keyNames; }
private:
    void loadKeyNames();
};

#endif
