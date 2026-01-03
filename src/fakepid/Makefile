# Makefile for fakepid LD_PRELOAD library

CC ?= gcc
CFLAGS = -fPIC -Wall -O2 -nostdlib
LDFLAGS = -shared -nostdlib

all: libfakepid.so libfakepid_embedded.h

libfakepid.so: fakepid.c
	$(CC) $(CFLAGS) -o libfakepid.so fakepid.c $(LDFLAGS)

libfakepid_embedded.h: libfakepid.so embed.sh
	./embed.sh

clean:
	rm -f libfakepid.so libfakepid_embedded.h

.PHONY: all clean
