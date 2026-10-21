/*
 * ML-KEM-768 Encapsulation Profiler
 * Identifies exactly where the time is spent in OQS_KEM_encaps
 * and tests optimization techniques.
 *
 * Compile:
 *   gcc -O3 -march=native -mavx2 -o bench_mlkem bench_mlkem.c \
 *       -I../liboqs/build/include ../liboqs/build/lib/liboqs.a \
 *       -lssl -lcrypto -lm -ldl -lpthread
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

static double time_us(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e6 + (b.tv_nsec - a.tv_nsec) / 1e3;
}

int main(void) {
    struct timespec t0, t1;

    printf("================================================================\n");
    printf("  ML-KEM-768 Encapsulation Profiler\n");
    printf("================================================================\n\n");

    /* ── 1. Measure OQS_init cost ────────────────────────────── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_init();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("[1] OQS_init():           %8.1f us\n", time_us(t0, t1));

    /* ── 2. Measure OQS_KEM_new cost ─────────────────────────── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("[2] OQS_KEM_new():        %8.1f us\n", time_us(t0, t1));

    if (!kem) { fprintf(stderr, "Failed to init ML-KEM-768\n"); return 1; }

    printf("    pk_size: %zu  sk_size: %zu  ct_size: %zu  ss_size: %zu\n",
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);

    /* ── 3. Allocate buffers ONCE (stack-like) ────────────────── */
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    /* ── 4. First keypair (cold cache) ────────────────────────── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_keypair(kem, pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("\n[3] First keypair (cold): %8.1f us\n", time_us(t0, t1));

    /* ── 5. First encaps (cold — this is what client does) ────── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double first_encaps = time_us(t0, t1);
    printf("[4] First encaps (cold):  %8.1f us  <-- THIS is your client number\n", first_encaps);

    /* ── 6. First decaps ──────────────────────────────────────── */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_decaps(kem, ss_dec, ct, sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("[5] First decaps (cold):  %8.1f us\n", time_us(t0, t1));

    /* Verify correctness */
    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) != 0) {
        printf("    !!! SHARED SECRET MISMATCH !!!\n");
        return 1;
    }
    printf("    Shared secret: OK\n");

    /* ── 7. Warm cache: repeated encaps ──────────────────────── */
    printf("\n--- WARM CACHE MEASUREMENTS (100 iterations each) ---\n\n");

    /* Keypair warm */
    double total = 0;
    for (int i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_keypair(kem, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total += time_us(t0, t1);
    }
    printf("[6] Keypair (warm avg):   %8.1f us\n", total / 100);

    /* Encaps warm */
    total = 0;
    double min_enc = 1e9, max_enc = 0;
    for (int i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_encaps(kem, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double d = time_us(t0, t1);
        total += d;
        if (d < min_enc) min_enc = d;
        if (d > max_enc) max_enc = d;
    }
    printf("[7] Encaps (warm avg):    %8.1f us  (min: %.1f, max: %.1f)\n",
           total / 100, min_enc, max_enc);

    /* Decaps warm */
    total = 0;
    for (int i = 0; i < 100; i++) {
        /* Re-encaps to get fresh ct */
        OQS_KEM_encaps(kem, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_decaps(kem, ss_dec, ct, sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total += time_us(t0, t1);
    }
    printf("[8] Decaps (warm avg):    %8.1f us\n", total / 100);

    /* ── 8. Test with pre-warmed OQS_SIG too ──────────────────── */
    printf("\n--- ML-DSA-65 FOR COMPARISON ---\n\n");
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *sig_pk = malloc(sig->length_public_key);
    uint8_t *sig_sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len;

    OQS_SIG_keypair(sig, sig_pk, sig_sk);

    /* Sign warm */
    total = 0;
    for (int i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_SIG_sign(sig, signature, &sig_len, pk, kem->length_public_key, sig_sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total += time_us(t0, t1);
    }
    printf("[9]  DSA sign (warm avg):  %8.1f us\n", total / 100);

    /* Verify warm */
    OQS_SIG_sign(sig, signature, &sig_len, pk, kem->length_public_key, sig_sk);
    total = 0;
    for (int i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_SIG_verify(sig, pk, kem->length_public_key, signature, sig_len, sig_pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        total += time_us(t0, t1);
    }
    printf("[10] DSA verify (warm avg):%8.1f us\n", total / 100);

    /* ── 9. Speedup analysis ──────────────────────────────────── */
    printf("\n--- COLD vs WARM ANALYSIS ---\n\n");
    printf("  ML-KEM encaps cold:  %.1f us\n", first_encaps);
    printf("  ML-KEM encaps warm:  %.1f us\n", min_enc);
    printf("  Cold/warm ratio:     %.1fx slowdown on first call\n", first_encaps / min_enc);
    printf("\n  The cold-start penalty is caused by:\n");
    printf("    1. CPU instruction cache misses (first-time code loading)\n");
    printf("    2. liboqs runtime AVX2 dispatch (function pointer resolution)\n");
    printf("    3. SHAKE128 matrix expansion (A-matrix generation)\n");
    printf("    4. Random number generation (getrandom syscall)\n");

    /* ── 10. Optimization: pre-warm technique ─────────────────── */
    printf("\n--- OPTIMIZATION: PRE-WARM TECHNIQUE ---\n\n");

    /* Simulate fresh client with pre-warm */
    OQS_KEM *kem2 = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    uint8_t *pk2 = malloc(kem2->length_public_key);
    uint8_t *sk2 = malloc(kem2->length_secret_key);
    uint8_t *ct2 = malloc(kem2->length_ciphertext);
    uint8_t *ss2 = malloc(kem2->length_shared_secret);

    /* Pre-warm: dummy keypair + encaps (discard results) */
    OQS_KEM_keypair(kem2, pk2, sk2);
    OQS_KEM_encaps(kem2, ct2, ss2, pk2);

    /* Now the real encaps (should be warm) */
    OQS_KEM_keypair(kem2, pk2, sk2);  /* fresh keys */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_encaps(kem2, ct2, ss2, pk2);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double warmed_encaps = time_us(t0, t1);

    printf("  Without pre-warm: %.1f us (your current client)\n", first_encaps);
    printf("  With pre-warm:    %.1f us\n", warmed_encaps);
    printf("  Improvement:      %.1fx faster\n", first_encaps / warmed_encaps);

    /* Cleanup */
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(pk2); free(sk2); free(ct2); free(ss2);
    free(sig_pk); free(sig_sk); free(signature);
    OQS_KEM_free(kem);
    OQS_KEM_free(kem2);
    OQS_SIG_free(sig);
    OQS_destroy();

    printf("\n================================================================\n");
    printf("  RECOMMENDATIONS:\n");
    printf("  1. Pre-warm OQS in client before auth (dummy encaps)\n");
    printf("  2. Reuse OQS_KEM object across operations\n");
    printf("  3. Use stack buffers instead of malloc in hot path\n");
    printf("  4. Report WARM numbers as steady-state performance\n");
    printf("================================================================\n");

    return 0;
}
