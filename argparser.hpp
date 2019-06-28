#ifndef _ARG_PARSER_HPP_
#define _ARG_PARSER_HPP_

#include <cstddef>

/*
    Define all the arguments in the C file.
    
    Once parseProgramArguments is called, it will iterate
    through all of the arguments passed through to the
    program and it will find matches to predefined arguments
    and call the callback function.

    Arguments that have no matches will be returned via.
    the overflow parameter.
*/

struct ARGPARSER_CmdArgument_t
{
    const char* cmd; // The argument prefix. (ex. "-d")
    const char* alias; // The argument alias. (ex. "--debug")
    const char* description; // A short description on what the argument does
    const void* callback; // A callback function. If this is NULL, nothing is called
};

struct ARGPARSER_Context_t
{
    bool debug;
    bool encrypt;
    bool decrypt;
    int key;
};

/*
Called in the main function.
# Parameters:
    'overflow' should be a pointer to allocated memory of a size that is a multiple of "sizeof(char*)" bytes. CAN BE NULL.
    'overflow_cb' is the number of bytes that were allocated for 'overflow'
    'overflow_count' is the number of overflowed arguments placed into the 'overflow' parameter.
*/
void ARGPARSER_parseProgramArguments(int argc, char* argv[], char* overflow[], size_t overflow_cb, unsigned* overflow_count);

// These are defined in the CPP file.
// FIXME: Shouldn't this be a "extern static const struct ARGPARSER_.."?
extern const struct ARGPARSER_CmdArgument_t argparser_arguments[];
extern struct ARGPARSER_Context_t argparser_context;
#endif

