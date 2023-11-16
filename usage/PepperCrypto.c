#include "PepperCrypto.h"

PepperInit Pepper;

void PepperCrypto__generate_random(unsigned char *buf, unsigned int buf_len) {
    randombytes(buf, buf_len);
}

void PepperCrypto__Blake2b__init(unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES], unsigned char *client_pk, unsigned char *server_pk) {
    if (!client_pk) {
        PepperCrypto__generate_random(nonce, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES);
    } else {
        blake2b_state hash;
        blake2b_init(&hash, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES, 0, 0);
        if (nonce)
            blake2b_update(&hash, nonce, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES);
        blake2b_update(&hash, client_pk, crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES);
        blake2b_update(&hash, server_pk, crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES);
        blake2b_final(&hash, nonce, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES);
    }
}

void PepperCrypto__Blake2b__increment(unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES]) {
    uint64_t nonceVal = 0;

    for (size_t i = 0; i < 24; ++i)
        nonceVal |= ((uint64_t)nonce[i]) << (8 * i);
    nonceVal += 2;

    for (size_t i = 0; i < 24; ++i) {
        nonce[i] = (uint8_t)(nonceVal & 0xFF);
        nonceVal >>= 8;
    }
}

void PepperCrypto__decrypt(const uint16_t id, unsigned char *buf, uint32_t buf_len) {
    if (id == 10101) {
        memcpy(Pepper.client_public_key, buf, crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES);
        buf += crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES;
        buf_len -= crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES;

        if (crypto_scalarmult_curve25519_tweet_base(Pepper.server_public_key, Pepper.server_secret_key)) {
            PepperCrypto__Blake2b__init(Pepper.nonce, Pepper.client_public_key, Pepper.server_public_key);

            if (crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(Pepper.s, Pepper.client_public_key, Pepper.server_secret_key)) {
                unsigned char temp_payload[buf_len + crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES];

                memset(temp_payload, 0, crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES);
                memcpy(temp_payload + crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES, buf, buf_len);

                unsigned char decrypted[sizeof(temp_payload)];

                if (crypto_secretbox_xsalsa20poly1305_tweet_open(decrypted, temp_payload, sizeof(temp_payload), Pepper.nonce, Pepper.s)) {;
                    unsigned char *decrypted_ptr = decrypted + 32;

                    memcpy(Pepper.decryptNonce, decrypted_ptr + crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES);
                    PepperCrypto__Blake2b__init(Pepper.decryptNonce, NULL, NULL);

                    buf = decrypted_ptr + 48;
                }
            }
        };
    } else if (Pepper.decryptNonce && id != 10100) {
        PepperCrypto__Blake2b__increment(Pepper.decryptNonce);

        unsigned char temp_payload[buf_len + 16];

        memset(temp_payload, 0, 16);
        memcpy(temp_payload + 16, buf, buf_len);

        unsigned char decrypted[sizeof(temp_payload)];

        if (crypto_secretbox_xsalsa20poly1305_tweet_open(decrypted, temp_payload, sizeof(temp_payload), Pepper.decryptNonce, Pepper.shared_encryption_key))
            memcpy(buf, decrypted + 32, sizeof(decrypted) - 32);
    }
}

void PepperCrypto__encrypt(const uint16_t id, unsigned char *buf, uint32_t buf_len) {
    if (id == 20104) {
        PepperCrypto__Blake2b__init(Pepper.decryptNonce, Pepper.client_public_key, Pepper.server_public_key);

        unsigned char temp_payload[buf_len + 56];

        memcpy(temp_payload, Pepper.encryptNonce, 24);
        memcpy(temp_payload + 24, Pepper.shared_encryption_key, 32);
        memcpy(temp_payload + 56, buf, buf_len);

        unsigned char padded_payload[sizeof(temp_payload) + 32];

        memset(padded_payload, 0, 32);
        memcpy(padded_payload + 32, temp_payload, sizeof(temp_payload));

        unsigned char encrypted[sizeof(padded_payload)];

        if (crypto_secretbox_xsalsa20poly1305_tweet(encrypted, padded_payload, sizeof(padded_payload), Pepper.decryptNonce, Pepper.s))
            memcpy(buf, encrypted + 16, sizeof(encrypted) - 16);
    } else if (id != 20100 || id != 20103) {
        PepperCrypto__Blake2b__increment(Pepper.encryptNonce);

        unsigned char padded_payload[buf_len + 32];
        memset(padded_payload, 0, 32);
        memcpy(padded_payload + 32, buf, buf_len);

        unsigned char encrypted[sizeof(padded_payload)];

        if (crypto_secretbox_xsalsa20poly1305_tweet(encrypted, padded_payload, sizeof(padded_payload), Pepper.encryptNonce, Pepper.shared_encryption_key))
            memcpy(buf, encrypted + 16, sizeof(encrypted) - 16);
    }
}

void PepperCrypto__init() {
    unsigned char PepperCrypto__server_secret_key[crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    for (int32_t i = 0; i < crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES; ++i)
        memcpy(Pepper.server_secret_key + i, PepperCrypto__server_secret_key + i, 1);

    PepperCrypto__generate_random(Pepper.shared_encryption_key, crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES); // PepperCrypto__shared_encryption_key
    PepperCrypto__generate_random(Pepper.encryptNonce, crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES); // PepperCrypto__encryptNonce

    PepperCrypto__Blake2b__init(Pepper.encryptNonce, 0, 0);

    Pepper.decryptNonce = 0;
    memset(Pepper.s, 0, crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES);
}