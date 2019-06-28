#ifndef _XMSG_HPP_
#define _XMSG_HPP_

#include <memory>
#include <string>
#include <vector>

#include "keychain.hpp"

constexpr float _xmsg_version = 1.0f;

class Application
{
private:
    int key;
    std::unique_ptr<Keychain> keychain;
public:
    Application(const int argc, char** argv);
    void start();
    static std::vector<uint8_t> generateRandomBytes(const int count);
private:
    void processArguments(const int argc, char** argv);
    std::string getInput();
};

#endif

