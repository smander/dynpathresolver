CC = gcc
CFLAGS = -Wall -Wextra -g -O0

.PHONY: all clean

all: libhidden.so test_binary

libhidden.so: libhidden.c
	$(CC) -fPIC -shared -fvisibility=hidden -o $@ $<

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f test_binary libhidden.so
