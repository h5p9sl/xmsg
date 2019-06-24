# Customize below to fit your system

# paths
PREFIX = /usr/local
CONFIG = $$HOME/.config/xmsg/xmsgkey.txt

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib

# flags
CFLAGS = -std=c++14 -Wall -O3 ${INCS} -DKEYFILE_PATH=\"${CONFIG}\"
LDFLAGS = -s ${LIBS}

# compiler and linker
CC = c++
