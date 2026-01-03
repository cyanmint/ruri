# Makefile for fakepid LD_PRELOAD library

CC ?= gcc
CFLAGS = -fPIC -Wall -O2
LDFLAGS ?= -shared -ldl

all: libfakepid.so libfakepid_embedded.h

libfakepid.so: fakepid.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o libfakepid.so fakepid.c

libfakepid_embedded.h: libfakepid.so embed.sh
	./embed.sh

clean:
	rm -f libfakepid.so libfakepid_embedded.h

.PHONY: all clean
