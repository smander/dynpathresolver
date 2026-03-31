CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libindirect.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libindirect.so: libindirect.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libindirect.so
