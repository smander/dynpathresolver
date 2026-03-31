CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libtimed.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libtimed.so: libtimed.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libtimed.so
