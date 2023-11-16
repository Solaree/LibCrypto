CC = gcc
CCFLAGS = -g -m32 -fPIC --std=gnu89 -I. -Wall
LDFLAGS = -shared

SRC_C = \
    tweetnacl/tweetnacl.c \
    tweetnacl/randombytes.c \
\
    blake2b/utils.c \
    blake2b/blake2b.c

all: libcrypto.so clean_bin

libcrypto.so: $(SRC_C:.c=.o)
	$(CC) -o $@ $^ $(LDFLAGS) $(CCFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CCFLAGS)

clean_bin:
	rm -rf $(SRC_C:.c=.o)

clean:
	rm -rf libcrypto.so
