CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libstack.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libstack.so: libstack.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libstack.so
