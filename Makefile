bin = sscall
ver = 0.1
obj = sscall.o

CC = gcc
CFLAGS += -Wall -Wextra -I/usr/local/include
LDFLAGS += -lao -lpthread -L/usr/local/lib

$(bin): $(obj)
	$(CC) $(CFLAGS) -o $@ $(obj) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf $(bin) $(obj)

all:
	make clean && make

.PHONY: all clean
