CC := gcc
LDFLAGS := -lssl -lcrypt -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: cs469projclient cs469projserver

cs469projclient: cs469projclient.o
	$(CC) $(CFLAGS) -o cs469projclient cs469projclient.o $(LDFLAGS)

cs469projclient.o: cs469projclient.c
	$(CC) $(CFLAGS) -c cs469projclient.c

cs469projserver: cs469projserver.o
	$(CC) $(CFLAGS) -o cs469projserver cs469projserver.o $(LDFLAGS)

cs469projserver.o: cs469projserver.c
	$(CC) $(CFLAGS) -c cs469projserver.c

clean:
	rm -f cs469projserver cs469projserver.o cs469projclient cs469projclient.o
