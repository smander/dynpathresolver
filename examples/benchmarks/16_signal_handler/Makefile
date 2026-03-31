CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -ldl

all: test_binary libsignal_payload.so libsignal_alt.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

libsignal_payload.so: libsignal_payload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

libsignal_alt.so: libsignal_alt.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary libsignal_payload.so libsignal_alt.so
