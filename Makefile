# xmsg
# See LICENSE file for copyright and license details.

include config.mk

SRC = main.cpp aes.c base64.cpp keychain.cpp xmsg.cpp
OBJ = ${SRC:.cpp=.o}
OBJ := ${OBJ:.c=.o}

all: options xmsg

options:
	@echo xmsg build options:
	@echo "CFLAGS	= ${CFLAGS}"
	@echo "LDFLAGS	= ${LDFLAGS}"
	@echo "CC	= ${CC}"
	@echo "OBJ	= ${OBJ}"

.c.o:
	@echo CC -c $<
	@${CC} -c ${CFLAGS} $<
.cpp.o:
	@echo CC -c $<
	@${CC} -c ${CFLAGS} $<

xmsg: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	@echo cleaning
	@rm -f xmsg ${OBJ}
