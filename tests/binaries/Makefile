CC = gcc
CFLAGS = -Wall -g -O0 -no-pie

all: indirect_jump

indirect_jump: indirect_jump.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f indirect_jump
