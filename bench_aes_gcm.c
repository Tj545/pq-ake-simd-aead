/*
 * bench_aes_gcm.c — AES-GCM microbenchmark for paper Table IV comparison
 *
 * Measures AES-128-GCM and AES-256-GCM at the same message profile as
 * chachapoly_simd.c: 33-byte plaintext, 12-byte nonce, no AAD.
 *
 * Two configurations reported:
 *   - Default OpenSSL (AES-NI + PCLMUL hardware acceleration)
 *   - Software fallback (OPENSSL_ia32cap disables AES-NI/PCLMUL)
 *
 * Compile:
 *   gcc -O3 -march=native bench_aes_gcm.c -lcrypto -o bench_aes_gcm
 *
 * Run:
 *   ./bench_aes_gcm              # with AES-NI
 *   OPENSSL_ia32cap="~0x200000200000000" ./bench_aes_gcm   # without AES-NI+PCLMUL
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define ITERATIONS 10000
#define MSG_LEN    33      /* Match chachapoly_simd measurement profile */
#define NONCE_LEN  12
#define TAG_LEN    16

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void die(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int aes_gcm_encrypt(const EVP_CIPHER *cipher,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *nonce,
                           const uint8_t *plaintext, size_t pt_len,
                           uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int outlen = 0, tmplen = 0;
    (void)key_len;
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL)) goto err;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto err;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)pt_len)) goto err;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen)) goto err;
    outlen += tmplen;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag)) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int aes_gcm_decrypt(const EVP_CIPHER *cipher,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *nonce,
                           const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t *tag,
                           uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int outlen = 0, tmplen = 0, rv;
    (void)key_len;
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL)) goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto err;
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)ct_len)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag)) goto err;
    rv = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return (rv > 0) ? (outlen + tmplen) : -1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static void bench_variant(const char *label, const EVP_CIPHER *cipher, size_t key_len) {
    uint8_t key[32];        /* Max 256 bits */
    uint8_t nonce[NONCE_LEN];
    uint8_t plaintext[MSG_LEN];
    uint8_t ciphertext[MSG_LEN + TAG_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t decrypted[MSG_LEN];

    /* Fill with deterministic-but-varied data */
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(0xA0 + i);
    for (size_t i = 0; i < NONCE_LEN; i++) nonce[i] = (uint8_t)i;
    for (size_t i = 0; i < MSG_LEN; i++) plaintext[i] = (uint8_t)(0x30 + i);

    /* Warm up (5 iterations) — absorb any first-call overhead */
    for (int i = 0; i < 5; i++) {
        aes_gcm_encrypt(cipher, key, key_len, nonce, plaintext, MSG_LEN, ciphertext, tag);
        aes_gcm_decrypt(cipher, key, key_len, nonce, ciphertext, MSG_LEN, tag, decrypted);
    }

    /* Correctness check */
    aes_gcm_encrypt(cipher, key, key_len, nonce, plaintext, MSG_LEN, ciphertext, tag);
    int ok = aes_gcm_decrypt(cipher, key, key_len, nonce, ciphertext, MSG_LEN, tag, decrypted);
    if (ok < 0 || memcmp(plaintext, decrypted, MSG_LEN) != 0) {
        fprintf(stderr, "%s: correctness FAILED\n", label);
        exit(2);
    }

    /* Time encryption */
    double t0 = now_us();
    for (int i = 0; i < ITERATIONS; i++) {
        nonce[11] = (uint8_t)(i & 0xFF);   /* vary nonce */
        aes_gcm_encrypt(cipher, key, key_len, nonce, plaintext, MSG_LEN, ciphertext, tag);
    }
    double t_enc = (now_us() - t0) / ITERATIONS;

    /* Time decryption */
    aes_gcm_encrypt(cipher, key, key_len, nonce, plaintext, MSG_LEN, ciphertext, tag);
    t0 = now_us();
    for (int i = 0; i < ITERATIONS; i++) {
        aes_gcm_decrypt(cipher, key, key_len, nonce, ciphertext, MSG_LEN, tag, decrypted);
    }
    double t_dec = (now_us() - t0) / ITERATIONS;

    printf("  %-30s Enc: %6.3f us  Dec: %6.3f us\n", label, t_enc, t_dec);
}

int main(void) {
    printf("========================================================\n");
    printf("  AES-GCM microbenchmark (OpenSSL %s)\n", OPENSSL_VERSION_TEXT);
    printf("  Message: %d bytes, nonce: %d bytes, tag: %d bytes\n",
           MSG_LEN, NONCE_LEN, TAG_LEN);
    printf("  Iterations per measurement: %d\n", ITERATIONS);

    const char *ia32cap = getenv("OPENSSL_ia32cap");
    if (ia32cap && *ia32cap) {
        printf("  Mode: OPENSSL_ia32cap=%s (AES-NI/PCLMUL disabled)\n", ia32cap);
    } else {
        printf("  Mode: default (AES-NI + PCLMUL enabled)\n");
    }
    printf("========================================================\n");

    bench_variant("AES-128-GCM", EVP_aes_128_gcm(), 16);
    bench_variant("AES-256-GCM", EVP_aes_256_gcm(), 32);

    printf("\n");
    return 0;
}
