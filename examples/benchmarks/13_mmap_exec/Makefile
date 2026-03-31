CC = gcc
CFLAGS = -Wall -g
LDFLAGS =

all: test_binary libmmap_payload.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libmmap_payload.so: libmmap_payload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libmmap_payload.so
