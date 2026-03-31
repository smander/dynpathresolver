CC = gcc
CFLAGS = -Wall -Wextra -g -O0

.PHONY: all clean

all: libcomputed.so test_binary

libcomputed.so: libcomputed.c
	$(CC) -fPIC -shared -fvisibility=hidden -o $@ $<

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f test_binary libcomputed.so
