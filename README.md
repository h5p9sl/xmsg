# [Xmsg](https://github.com/h5p9sl/xmsg)
Xmsg is a lightweight message encryption program that provides the user with message encryption/decryption using secret keys.

Xmsg is **not** a chat client. It is simply a text encryption program.

## Feature Overview
+ AES-256-CBC for encryption and decryption
+ Prepends metadata in front of encrypted string
    + Metadata includes information like:
        + Message Length
        + Initialization Vector
+ "Key chain" feature, which allows the user to manage multiple encryption keys.
    + User can create and destroy encryption keys using "--createkey" and "--deletekey" flags

## Contributing
Contributions are welcome! Beware that the source code may be a *little messy* and poorly documented, but I'm doing my best to clean it up over time.

Please feel free to submit bug reports in the form of issues, along with a detailed description of the bug, and how to replicate it.

## Acknowledgments
https://github.com/kokke/tiny-AES-c
+ aes.h
+ aes.hpp
+ aes.cpp

https://github.com/ReneNyffenegger/cpp-base64
+ base64.hpp
+ base64.cpp

