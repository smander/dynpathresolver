CC = gcc
CFLAGS = -Wall -Wextra -g -O0

.PHONY: all clean

all: libstage1.so libstage2.so test_binary

libstage1.so: libstage1.c
	$(CC) -fPIC -shared -fvisibility=hidden -o $@ $< -ldl

libstage2.so: libstage2.c
	$(CC) -fPIC -shared -fvisibility=hidden -o $@ $<

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f test_binary libstage1.so libstage2.so
