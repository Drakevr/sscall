BIN = sscall
VER = 0.2-rc1
SRC = sscall.c
OBJ = ${SRC:.c=.o}

PREFIX = /usr
MANDIR = /man/man1
MANDST = ${PREFIX}${MANDIR}

CC = gcc

# These might need updating, depending on your system
INCS = -I/usr/local/include
LIBS = -L/usr/local/lib

CFLAGS += -Wall -Wextra -DVERSION=\"${VER}\" ${INCS}
# Add -lsocket if you are building on Solaris
LDFLAGS += -lao -lpthread -lspeex -lsamplerate ${LIBS}

$(BIN): ${OBJ}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJ}

%.o: %.c
	${CC} ${CFLAGS} -c -o $@ $<

clean:
	@rm -rf ${BIN} ${OBJ}

all:
	sscall

install:
	cp -f ${BIN} ${PREFIX}/bin
	chmod 755 ${PREFIX}/bin/${BIN}
	mkdir -p ${MANDST}
	gzip -c man/man1/sscall.1 > man/man1/sscall.1.gz
	mv -f man/man1/sscall.1.gz ${MANDST}
	chmod 644 ${MANDST}/sscall.1.gz

uninstall:
	rm -f ${PREFIX}/bin/${BIN}
	rm -f ${MANDST}/sscall.1.gz

.PHONY: all clean install uninstall
