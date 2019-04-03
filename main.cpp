// Acknowledgments:
//  https://github.com/ReneNyffenegger/cpp-base64
//  https://github.com/kokke/tiny-AES-c

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

#include "xmsg.hpp"

int main(int argc, char* argv[]) {
    Application app(argc, argv);

    puts("Tip: Launch this program with the \"--help\" flag to see a list of arguments.");
    app.start();
    return 0;
}

