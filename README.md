# LibCrypto

>  *This library contains simular to original crypto/hashing functions, which Supercell use since they moved to TweetNaCl & Blake2b*

## Basic Crypto Functions

```void randombytes(unsigned char *buf, unsigned int buf_len)```

```int crypto_scalarmult_curve25519_tweet_base(unsigned char *q, const unsigned char *n)```

```int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(unsigned char *y, unsigned char *x)```

```int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(unsigned char *k, const unsigned char *y, const unsigned char *x)```

```int crypto_box_curve25519xsalsa20poly1305_tweet_afternm(unsigned char *c, const unsigned char *m, unsigned long long d, const unsigned char *n, const unsigned char *k)```

```int crypto_box_curve25519xsalsa20poly1305_tweet(unsigned char *c, const unsigned char *m, unsigned long long d, const unsigned char *n, const unsigned char *y, const unsigned char *x)```

```int crypto_box_curve25519xsalsa20poly1305_tweet_open(unsigned char *m, const unsigned char *c, unsigned long long d, const unsigned char *n, const unsigned char *y, const unsigned char *x)```

```int crypto_secretbox_xsalsa20poly1305_tweet(unsigned char *c, const unsigned char *m, unsigned long long d, const unsigned char *n, const unsigned char *k)```

```int crypto_secretbox_xsalsa20poly1305_tweet_open(unsigned char *m, const unsigned char *c, unsigned long long d, const unsigned char *n, const unsigned char *k)```

## Basic Hash Functions

```int blake2b_init(blake2b_state *S, size_t outlen, const void *key, size_t keylen)```

```int blake2b_update(blake2b_state *S, const void *in, size_t inlen)```

```int blake2b_final(blake2b_state *S, void *out, size_t outlen)```

```int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)```

```void blake2b_increment_counter(blake2b_state *S, const unsigned int inc)```

---

**Library can be used in C/C++, Java (JNA), *(maybe C# but untested)***

Some of precompiled binaries are put in **/lib/** folder