/*
 * ChaCha20-Poly1305 AEAD — AVX2 SIMD Batch + Scalar Baseline (UPDATED 2026)
 *
 * Changes from prior revision:
 *   FIX-1: Strict-aliasing UB / unaligned reads in poly1305_init and
 *          poly1305_blocks replaced with memcpy-based load helpers.
 *          Previous: *(const uint32_t *)(key + 3) — UB per C99 §6.5p7,
 *          also unaligned on architectures that fault on unaligned access.
 *   FIX-2: chacha20_batch4 no longer rebuilds state per 64 bytes
 *          (see chacha20_avx2.h FIX-1).
 *   FIX-3: NULL checks on malloc paths.
 *   FIX-4: Tag comparison was already constant-time — preserved and
 *          documented.
 *   NOTE:  Poly1305 remains scalar-per-stream (4 sequential calls in
 *          chachapoly_batch4_avx2). Lane-parallel Poly1305 is a
 *          separate effort — see LANE_PARALLEL_POLY1305.md.
 */

#include "chachapoly_simd.h"
#include "chacha20_avx2.h"
#include <string.h>
#include <stdlib.h>
#include <cpuid.h>

/* ================================================================
 *  Safe LE 32-bit load — fixes strict-aliasing UB
 * ================================================================ */

static inline uint32_t load32_le(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/* ================================================================
 *  Poly1305 — Scalar implementation (RFC 8439 §2.5)
 * ================================================================ */

#define POLY_BLOCK 16

typedef struct {
    uint32_t r[5], h[5], pad[4];
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *c, const uint8_t key[32]) {
    /* FIX-1: replace UB pointer casts with safe loads */
    c->r[0] =  load32_le(key +  0)       & 0x3ffffff;
    c->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03;
    c->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
    c->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fff;
    c->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) c->h[i] = 0;
    for (int i = 0; i < 4; i++)
        c->pad[i] = load32_le(key + 16 + i * 4);
}

static void poly1305_blocks(poly1305_ctx *c, const uint8_t *m, size_t bytes,
                             uint32_t hibit) {
    uint32_t r0=c->r[0], r1=c->r[1], r2=c->r[2], r3=c->r[3], r4=c->r[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=c->h[0], h1=c->h[1], h2=c->h[2], h3=c->h[3], h4=c->h[4];

    while (bytes >= POLY_BLOCK) {
        /* FIX-1: safe loads instead of UB pointer casts */
        h0 += (load32_le(m +  0))      & 0x3ffffff;
        h1 += (load32_le(m +  3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m +  6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m +  9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t cc;
        cc = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += cc; cc = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += cc; cc = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += cc; cc = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += cc; cc = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3ffffff;
        h1 += cc;

        m     += POLY_BLOCK;
        bytes -= POLY_BLOCK;
    }
    c->h[0]=h0; c->h[1]=h1; c->h[2]=h2; c->h[3]=h3; c->h[4]=h4;
}

static void poly1305_finish(poly1305_ctx *c, uint8_t mac[16]) {
    uint32_t h0=c->h[0], h1=c->h[1], h2=c->h[2], h3=c->h[3], h4=c->h[4];
    uint32_t cc, g0, g1, g2, g3, g4, mask;
    uint64_t f;

    cc = h1 >> 26; h1 &= 0x3ffffff;
    h2 += cc; cc = h2 >> 26; h2 &= 0x3ffffff;
    h3 += cc; cc = h3 >> 26; h3 &= 0x3ffffff;
    h4 += cc; cc = h4 >> 26; h4 &= 0x3ffffff;
    h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3ffffff;
    h1 += cc;

    g0 = h0+5;  cc = g0>>26; g0 &= 0x3ffffff;
    g1 = h1+cc; cc = g1>>26; g1 &= 0x3ffffff;
    g2 = h2+cc; cc = g2>>26; g2 &= 0x3ffffff;
    g3 = h3+cc; cc = g3>>26; g3 &= 0x3ffffff;
    g4 = h4+cc - (1u<<26);

    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0&mask)|g0; h1 = (h1&mask)|g1;
    h2 = (h2&mask)|g2; h3 = (h3&mask)|g3;
    h4 = (h4&mask)|g4;

    h0 = h0 | (h1<<26);
    h1 = (h1>>6)  | (h2<<20);
    h2 = (h2>>12) | (h3<<14);
    h3 = (h3>>18) | (h4<<8);

    f = (uint64_t)h0 + c->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + c->pad[1] + (f>>32);   h1 = (uint32_t)f;
    f = (uint64_t)h2 + c->pad[2] + (f>>32);   h2 = (uint32_t)f;
    f = (uint64_t)h3 + c->pad[3] + (f>>32);   h3 = (uint32_t)f;

    memcpy(mac +  0, &h0, 4);
    memcpy(mac +  4, &h1, 4);
    memcpy(mac +  8, &h2, 4);
    memcpy(mac + 12, &h3, 4);
    memset(c, 0, sizeof(*c));
}

/*
 * Full Poly1305 MAC over ciphertext per RFC 8439, with AAD = empty.
 * The lengths block encodes AAD length = 0 and CT length, as required
 * even when AAD is empty.
 */
static void poly1305_mac(uint8_t mac[16], const uint8_t *ct, size_t ct_len,
                          const uint8_t poly_key[32])
{
    poly1305_ctx ctx;
    poly1305_init(&ctx, poly_key);

    size_t full = ct_len & ~(size_t)15;
    if (full)
        poly1305_blocks(&ctx, ct, full, 0x01000000);

    size_t tail = ct_len - full;
    if (tail) {
        uint8_t last[POLY_BLOCK];
        memset(last, 0, POLY_BLOCK);
        memcpy(last, ct + full, tail);
        last[tail] = 1;
        poly1305_blocks(&ctx, last, POLY_BLOCK, 0);
    }

    /* RFC 8439 lengths block: aad_len (8 LE) || ct_len (8 LE) */
    uint8_t lens[POLY_BLOCK];
    memset(lens, 0, POLY_BLOCK);  /* AAD length = 0 */
    uint64_t ct64 = ct_len;
    memcpy(lens + 8, &ct64, 8);
    poly1305_blocks(&ctx, lens, POLY_BLOCK, 0);

    poly1305_finish(&ctx, mac);
}

/* Constant-time tag comparison — preserved from original.
 * Uses bitwise AND to force full-length comparison regardless of mismatch. */
static int ct_memcmp_16(const uint8_t *a, const uint8_t *b) {
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= (a[i] ^ b[i]);
    return diff;  /* 0 if equal, non-zero otherwise */
}

/* ================================================================
 *  Scalar ChaCha20 — pure C reference
 * ================================================================ */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void chacha20_qr_scalar(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d = ROTL32(*d ^ *a, 16);
    *c += *d; *b = ROTL32(*b ^ *c, 12);
    *a += *b; *d = ROTL32(*d ^ *a,  8);
    *c += *d; *b = ROTL32(*b ^ *c,  7);
}

static void chacha20_block_scalar(const uint32_t in[16], uint32_t out[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    for (int i = 0; i < 10; i++) {
        chacha20_qr_scalar(&x[0],&x[4],&x[ 8],&x[12]);
        chacha20_qr_scalar(&x[1],&x[5],&x[ 9],&x[13]);
        chacha20_qr_scalar(&x[2],&x[6],&x[10],&x[14]);
        chacha20_qr_scalar(&x[3],&x[7],&x[11],&x[15]);
        chacha20_qr_scalar(&x[0],&x[5],&x[10],&x[15]);
        chacha20_qr_scalar(&x[1],&x[6],&x[11],&x[12]);
        chacha20_qr_scalar(&x[2],&x[7],&x[ 8],&x[13]);
        chacha20_qr_scalar(&x[3],&x[4],&x[ 9],&x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void chacha20_init_scalar(uint32_t st[16], const uint8_t key[32],
                                  const uint8_t nonce[12], uint32_t counter) {
    st[0]=0x61707865; st[1]=0x3320646e;
    st[2]=0x79622d32; st[3]=0x6b206574;
    for (int i = 0; i < 8; i++)
        st[4+i] = load32_le(key + i*4);
    st[12] = counter;
    for (int i = 0; i < 3; i++)
        st[13+i] = load32_le(nonce + i*4);
}

int chachapoly_scalar(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    uint8_t *tag,
    int encrypt)
{
    uint32_t st[16], out[16];

    /* Block 0 → Poly1305 one-time key */
    uint8_t poly_key[32];
    chacha20_init_scalar(st, key, nonce, 0);
    chacha20_block_scalar(st, out);
    memcpy(poly_key, out, 32);

    if (encrypt) {
        size_t done = 0;
        uint32_t blk = 1;
        while (done < length) {
            chacha20_init_scalar(st, key, nonce, blk);
            chacha20_block_scalar(st, out);
            uint8_t *ks = (uint8_t *)out;
            size_t n = (length - done > 64) ? 64 : (length - done);
            for (size_t j = 0; j < n; j++)
                output[done + j] = input[done + j] ^ ks[j];
            done += n;
            blk++;
        }
        poly1305_mac(tag, output, length, poly_key);
    } else {
        /* Verify-then-decrypt (RFC 8439 §2.8 ordering) */
        uint8_t computed[16];
        poly1305_mac(computed, input, length, poly_key);
        if (ct_memcmp_16(computed, tag) != 0) {
            memset(poly_key, 0, 32);
            return -1;
        }

        size_t done = 0;
        uint32_t blk = 1;
        while (done < length) {
            chacha20_init_scalar(st, key, nonce, blk);
            chacha20_block_scalar(st, out);
            uint8_t *ks = (uint8_t *)out;
            size_t n = (length - done > 64) ? 64 : (length - done);
            for (size_t j = 0; j < n; j++)
                output[done + j] = input[done + j] ^ ks[j];
            done += n;
            blk++;
        }
    }

    /* Zero sensitive material */
    memset(poly_key, 0, 32);
    memset(st, 0, sizeof(st));
    memset(out, 0, sizeof(out));
    return 0;
}

/* ================================================================
 *  AVX2 Batched AEAD — 4 messages in parallel
 *
 *  ChaCha20 is lane-parallel SIMD (real AVX2 across 4 streams).
 *  Poly1305 runs sequentially per stream (interface batching only).
 *  See LANE_PARALLEL_POLY1305.md for the open work to vectorize Poly1305.
 * ================================================================ */

int chachapoly_batch4_avx2(
    const uint8_t *keys[4],
    const uint8_t *nonces[4],
    const uint8_t *inputs[4],
    uint8_t *outputs[4],
    const size_t lengths[4],
    uint8_t *tags[4],
    int encrypt)
{
    /* 1. Derive 4 Poly1305 one-time keys from block 0, in parallel. */
    uint8_t pk0[64], pk1[64], pk2[64], pk3[64];
    uint8_t *pks[4] = {pk0, pk1, pk2, pk3};
    chacha20_generate_batch4(keys, nonces, 0, pks);

    if (encrypt) {
        /* 2. Encrypt streams in parallel (counter starts at 1) */
        chacha20_batch4(keys, nonces, inputs, outputs, lengths);

        /* 3. Compute Poly1305 tag per stream (scalar; sequential) */
        for (int i = 0; i < 4; i++)
            poly1305_mac(tags[i], outputs[i], lengths[i], pks[i]);
    } else {
        /* 2. Verify tags BEFORE decryption (RFC 8439 §2.8) */
        for (int i = 0; i < 4; i++) {
            uint8_t computed[16];
            poly1305_mac(computed, inputs[i], lengths[i], pks[i]);
            if (ct_memcmp_16(computed, tags[i]) != 0) {
                /* Zero all Poly keys before returning failure */
                memset(pk0, 0, 64); memset(pk1, 0, 64);
                memset(pk2, 0, 64); memset(pk3, 0, 64);
                return -1;
            }
        }

        /* 3. Decrypt streams in parallel */
        chacha20_batch4(keys, nonces, inputs, outputs, lengths);
    }

    /* Zero sensitive material */
    memset(pk0, 0, 64); memset(pk1, 0, 64);
    memset(pk2, 0, 64); memset(pk3, 0, 64);
    return 0;
}

/* ================================================================
 *  CPU feature detection
 * ================================================================ */

int chachapoly_simd_available(void) {
#ifdef __AVX2__
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx) || eax < 7)
        return 0;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return (ebx & bit_AVX2) != 0;
#endif
    return 0;
}
