CC = gcc
CFLAGS = -Wall -Wextra -g -O0

.PHONY: all clean

all: libplugin.so test_binary

libplugin.so: libplugin.c
	$(CC) -fPIC -shared -fvisibility=hidden -o $@ $<

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f test_binary libplugin.so
