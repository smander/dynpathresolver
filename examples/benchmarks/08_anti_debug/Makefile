CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libprotected.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libprotected.so: libprotected.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libprotected.so
