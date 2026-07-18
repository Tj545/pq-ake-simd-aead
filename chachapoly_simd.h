/*
 * ChaCha20-Poly1305 AEAD with AVX2 SIMD Batching
 * Processes 4 independent AEAD operations in parallel
 */

#ifndef CHACHAPOLY_SIMD_H
#define CHACHAPOLY_SIMD_H

#include <stdint.h>
#include <stddef.h>

/*
 * Encrypt/Decrypt 4 messages in parallel using AVX2.
 * ChaCha20 keystream generation is vectorized; Poly1305 remains scalar.
 *
 * @return 0 on success, -1 on tag verification failure (decrypt only)
 */
int chachapoly_batch4_avx2(
    const uint8_t *keys[4],
    const uint8_t *nonces[4],
    const uint8_t *inputs[4],
    uint8_t *outputs[4],
    const size_t lengths[4],
    uint8_t *tags[4],
    int encrypt
);

/*
 * Scalar single-message ChaCha20-Poly1305 (for baseline comparison).
 * Uses a simple reference implementation — NOT AVX2.
 */
int chachapoly_scalar(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *input,
    uint8_t *output,
    size_t length,
    uint8_t *tag,
    int encrypt
);

/* Check if AVX2 is available on this CPU */
int chachapoly_simd_available(void);

#endif /* CHACHAPOLY_SIMD_H */
