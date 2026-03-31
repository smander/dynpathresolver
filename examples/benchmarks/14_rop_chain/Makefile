CC = gcc
CFLAGS = -Wall -g -fno-stack-protector
LDFLAGS = -ldl

all: test_binary librop_payload.so

test_binary: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

librop_payload.so: librop_payload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f test_binary librop_payload.so
