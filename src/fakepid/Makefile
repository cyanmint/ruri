# Makefile for fakepid LD_PRELOAD library

CC = gcc
CFLAGS = -fPIC -Wall -O2
LDFLAGS = -shared -ldl

all: libfakepid.so

libfakepid.so: fakepid.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o libfakepid.so fakepid.c

clean:
	rm -f libfakepid.so

.PHONY: all clean
