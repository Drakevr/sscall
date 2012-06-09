bin = sscall
ver = 0.1
obj = sscall.o

DESTDIR ?=
PREFIX ?= /usr
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

uninstall:
	rm -f $(dst)/bin/$(bin)

.PHONY: all clean
