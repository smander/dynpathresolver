CC = gcc
CFLAGS = -Wall -g
LDFLAGS =

all: test_binary libmanual.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libmanual.so: libmanual.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libmanual.so
