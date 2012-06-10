bin = sscall
ver = 0.1
obj = sscall.o

DESTDIR ?=
PREFIX ?= /usr
MANDIR ?= /usr/man/man1
mandst = ${DESTDIR}${MANDIR}
dst = ${DESTDIR}${PREFIX}

CC = gcc
CFLAGS += -Wall -Wextra -I/usr/local/include
LDFLAGS += -lao -lpthread -lspeex -lsamplerate -L/usr/local/lib

$(bin): $(obj)
	$(CC) $(CFLAGS) -o $@ $(obj) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf $(bin) $(obj)

all:
	make

install:
	cp -f $(bin) $(dst)/bin
	chmod 755 $(dst)/bin/$(bin)
	mkdir -p $(mandst)
	cp -f man/man1/sscall.1 $(mandst)

uninstall:
	rm -f $(dst)/bin/$(bin)
	rm -f $(mandst)/sscall.1

.PHONY: all clean
