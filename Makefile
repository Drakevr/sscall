bin = sscall
ver = 0.1
src = sscall.c

CC = gcc
CFLAGS += -Wall -Wextra -I/usr/local/include
LDFLAGS += -lao -lpthread -L/usr/local/lib

all: $(bin)

%: %.c 
	$(CC) -o $(bin) $(src) $(CFLAGS) $(LDFLAGS)

clean:
	@rm -rf $(bin)

.PHONY: all clean
