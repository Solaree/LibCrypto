CC = gcc
CCFLAGS = -g -m32 -fPIC -shared --std=gnu99 -I. -Wall
SRC_C = \
    PepperCrypto.c
LIBS = ../lib/gcc-linux-gnueabi/i386/libcrypto.so

all: PepperCrypto.so clean_bin

PepperCrypto.so: $(SRC_C:.c)
	$(CC) -o $@ $^ $(SRC_C) $(CCFLAGS) $(LIBS)
clean_bin:
	rm -rf $(SRC_C:.c=.o)
clean:
	rm -rf PepperCrypto.so