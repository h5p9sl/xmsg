# [Xmsg](https://github.com/h5p9sl/xmsg)
Xmsg is a lightweight message encryption program that provides the user with message encryption/decryption using secret keys.

Xmsg is **not** a chat client. It is simply a text encryption program.

## Building/Installing
0) Clone the github repository
```sh
git clone https://github.com/h5p9sl/xmsg
cd xmsg
```
1) Customize config.mk to suit your operating system

### Building

1) Run make
```sh
make xmsg
```

### Installing

1) Edit the config.mk file to suit your operating system
2) Run make as root, if needed
```sh
make clean install
```

## How to use
Run `xmsg -h` to get a list of commands.

### Examples
+ `echo 'Hello World!" | xmsg --key 2 --encrypt`
+ `cat file.txt | xmsg --key 0 --encrypt`
+ `xmsg --key 0 -e < file.txt`
+ `xmsg -k0 -e < file.txt > file.txt.enc`

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

