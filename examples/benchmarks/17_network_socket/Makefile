CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libnetplugin.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libnetplugin.so: libnetplugin.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libnetplugin.so
