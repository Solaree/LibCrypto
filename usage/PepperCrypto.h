#ifndef PEPPERCRYPTO_H
#define PEPPERCRYPTO_H

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2b_state {
    uint64_t h[8];                   // Chained state
    uint64_t t[2];                   // Total number of bytes
    uint64_t f[2];                   // Last block flag
    uint8_t buf[BLAKE2B_BLOCKBYTES]; // Input buffer
    size_t buflen;                   // Size of buffer
    size_t outlen;                   // Digest size
} blake2b_state;

extern int blake2b_init(blake2b_state *S, size_t outlen, const void *key, size_t keylen);
extern int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
extern int blake2b_final(blake2b_state *S, void *out, size_t outlen);
extern int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

#define crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES 32
#define crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES 32
#define crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES 32
#define crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES 24
#define crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES 32
#define crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES 16

typedef struct {
    unsigned char     server_secret_key[crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES];
    unsigned char     server_public_key[crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES];
    unsigned char                      s[crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES];
    unsigned char     client_public_key[crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES];
    unsigned char shared_encryption_key[crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES];

    unsigned char                     nonce[crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES];

    unsigned char                                                                     *encryptNonce;
    unsigned char                                                                     *decryptNonce;
} PepperInit;
extern PepperInit Pepper;

extern void randombytes(unsigned char *buf, unsigned int buf_len);

extern int crypto_scalarmult_curve25519_tweet_base(unsigned char *q, const unsigned char *n);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(unsigned char *k, const unsigned char *y, const unsigned char *x);
extern int crypto_secretbox_xsalsa20poly1305_tweet(unsigned char *c, const unsigned char *m, unsigned long long d, const unsigned char *n, const unsigned char *k);
extern int crypto_secretbox_xsalsa20poly1305_tweet_open(unsigned char *m, const unsigned char *c, unsigned long long d, const unsigned char *n, const unsigned char *k);

/* Blake2b Nonce Init */
static void PepperCrypto__Blake2b__init(unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES], unsigned char *client_pk, unsigned char *server_pk);

/* Blake2b Nonce Increment */
static void PepperCrypto__Blake2b__increment(unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES]);

/* Pepper Decryption Implementation */
static void PepperCrypto__decrypt(const uint16_t id, unsigned char *buf, uint32_t buf_len);

/* Pepper Encryption Implementation */
static void PepperCrypto__encrypt(const uint16_t id, unsigned char *buf, uint32_t buf_len);

/* PepperCrypto Initialization */
static void PepperCrypto__init();
#endif // !PEPPERCRYPTO_H