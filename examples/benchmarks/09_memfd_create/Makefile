CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libmemfd_payload.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libmemfd_payload.so: libmemfd_payload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libmemfd_payload.so
