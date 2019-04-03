// Acknowledgments:
//  https://github.com/ReneNyffenegger/cpp-base64
//  https://github.com/kokke/tiny-AES-c

#include <cstdio>

#include "xmsg.hpp"

int main(int argc, char* argv[]) {
    Application app(argc, argv);

    puts("Tip: Launch this program with the \"--help\" flag to see a list of arguments.");
    app.start();
    return 0;
}

