CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libmulti.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libmulti.so: libmulti.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libmulti.so
