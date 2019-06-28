#include "argparser.hpp"

#include "keychain.hpp"
#include "xmsg.hpp"

#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdbool>

#define argparser_arguments ARGS

void cmd_help(int argc, char* argv[]);
void cmd_version(int argc, char* argv[]);
void cmd_debug(int argc, char* argv[]);
void cmd_key(int argc, char* argv[]);
void cmd_dumpkeys(int argc, char* argv[]);
void cmd_encrypt(int argc, char* argv[]);
void cmd_decrypt(int argc, char* argv[]);
void cmd_createkey(int argc, char* argv[]);
void cmd_deletekey(int argc, char* argv[]);

// Defined as an extern variable in the H file
const struct ARGPARSER_CmdArgument_t ARGS[] = {
    { "-h", "--help", "Provides a list of possible arguments that can be passed to the program.", (void*)&cmd_help },
    { "-v", "--version", "display xmsg version.", (void*)&cmd_version },
    { "-D", "--debug", "enable debug messages.", (void*)&cmd_debug },
    { "-k", "--key", "set encryption key to use.", (void*)&cmd_key },
    { "-K", "--dumpkeys", "dumps available encryption keys.", (void*)&cmd_dumpkeys },
    { "-e", "--encrypt", "enables encryption mode.", (void*)&cmd_encrypt },
    { "-d", "--decrypt", "enables decryption mode.", (void*)&cmd_decrypt },
    { "", "--createkey", "create encryption key.", (void*)&cmd_createkey },
    { "", "--deletekey", "delete encryption key.", (void*)&cmd_deletekey }
};
struct ARGPARSER_Context_t argparser_context;

void ARGPARSER_parseProgramArguments(int argc, char* argv[], char* overflow[], size_t overflow_cb, unsigned* overflow_count) {
    unsigned c_overflow = 0;

    int subargs_count;
    const char** subargs;

    subargs = (const char**)malloc(sizeof(char*) * argc);
    subargs_count = 0;

    for (int i = 0; i < argc; i++) {
        bool found = false;

        std::string str;
        for (unsigned j = 0; j < sizeof(ARGS) / sizeof(ARGS[0]); j++) {
            int type = 0;
            str.clear();

            if (strcmp(argv[i], ARGS[j].alias) == 0)
            {
                for (int k = i + 1; k < argc; k++) {
                    // If the next argument starts with '-', break
                    if (argv[k][0] == '-') break;
                    subargs[subargs_count] = argv[k];
                    subargs_count++;
                }
                type = 1;
                found = true;
            }
            else if (strlen(ARGS[j].cmd) > 1 &&
                strncmp(argv[i], ARGS[j].cmd, strlen(ARGS[j].cmd)) == 0)
            {
                for (int k = 2; argv[i][k] >= '0' && argv[i][k] <= '9'; k++) {
                    str.push_back(argv[i][k]);
                }
                type = 2;
                found = true;
            }
            // Call the callback function if it's not NULL to avoid segfaults
            if (ARGS[j].callback == NULL) continue;

            switch (type) {
            case 1:
                i += subargs_count;
                ((void(*)(int,const char*[]))ARGS[j].callback)(subargs_count, subargs);
                break;
            case 2:
                subargs[0] = str.data();
                subargs_count = 1;
                ((void(*)(int,const char*[]))ARGS[j].callback)(subargs_count, subargs);
                break;
            }

            if (type != 0) break;
        }

        // Push argument to overflow buffer if no match is found
        if (!found && overflow) {
            // Ensure there are no segfaults
            if ((c_overflow + 1) * sizeof(char*) > overflow_cb) {
                continue;
            }
            overflow[c_overflow++] = argv[i];
            if (overflow_count != (unsigned*)NULL) {
                *overflow_count = c_overflow;
            }
        }

    }
    free(subargs);
}

void cmd_help(int argc, char* argv[]) {
    for (unsigned i = 0; i < sizeof(ARGS) / sizeof(ARGS[1]); i++) {
        printf("%s    %s    %s\n", ARGS[i].cmd, ARGS[i].alias, ARGS[i].description);
    }
}

void cmd_version(int argc, char* argv[]) {
    printf("xmsg version %.1f\n", _xmsg_version);
    exit(0);
}

void cmd_debug(int argc, char* argv[]) {
    argparser_context.debug = true;
}

void cmd_key(int argc, char* argv[]) {
    if (argc != 1) {
        fputs("Invalid number of paramaters for --key:", stderr);
        for (int i = 0; i < argc; i++) {
            printf("%i: %s\n", i, argv[i]);
        }
    }
    sscanf(argv[0], "%d", &argparser_context.key);
}

void cmd_dumpkeys(int argc, char* argv[]) {
    // Creates Keychain object with invalid key ID.
    // Prints out all the available encryption keys
    Keychain keychain(-1);
    exit(0);
}

void cmd_encrypt(int argc, char* argv[]) {
    argparser_context.encrypt = true;
}

void cmd_decrypt(int argc, char* argv[]) {
    argparser_context.decrypt = true;
}

void cmd_createkey(int argc, char* argv[]) {
    Keychain::createKey();
    exit(0);
}

void cmd_deletekey(int argc, char* argv[]) {
    Keychain* keychain = new Keychain(0);
    keychain->deleteKey();
    exit(0);
}

