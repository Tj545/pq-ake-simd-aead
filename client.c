/*
 * Post-Quantum Secure Client (CORRECTED)
 * ========================================
 * Authentication : ML-DSA-65 (verify) + ML-KEM-768 (encaps)
 * Data AEAD     : ChaCha20-Poly1305 (scalar, single-message)
 * KDF           : SHAKE256 (transcript-bound)
 *
 * SECURITY FIXES APPLIED (matching server.c):
 *   [SECURITY-1] Server session nonce ns received and bound into KDF
 *   [SECURITY-2] Transcript-bound signature: Verify(H(pk_sig||pk_kem||ns))
 *   [SECURITY-3] Transcript-bound KDF: SHAKE256("PQ-AKE"||ss||pk_sig||pk_kem||ns||ct)
 *   [SECURITY-4] Directional keys: key_s2c != key_c2s (prevents reflection)
 *   [SECURITY-5] Monotonic nonces with replay detection
 *   [SECURITY-6] Public key length validation
 *   [SECURITY-7] Secrets zeroed before free
 *
 * These changes align with a ProVerif model proving:
 *   - Secrecy of session keys and messages
 *   - Injective server authentication (Q8)
 *   - Message authenticity (Q7)
 *   - Key agreement integrity (Q6)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/random.h>

#ifndef u_int
#define u_int unsigned int
#endif

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include "chachapoly_simd.h"

/* ── Configuration ─────────────────────────────────────────────── */
#define SERVER_IP          "127.0.0.1"
#define SERVER_PORT        9000
#define KEY_LEN            32
#define NONCE_LEN          12
#define TAG_LEN            16
#define SESSION_NONCE_LEN  32       /* [SECURITY-1] must match server */

/* ── Timing helper ─────────────────────────────────────────────── */
static double time_us(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e6 + (b.tv_nsec - a.tv_nsec) / 1e3;
}

/* FIX (2026): handle getrandom partial reads and failures.
 * Old code silently ignored errors via (void)r. */
static void rand_bytes(uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = getrandom(buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "FATAL: getrandom failed: %s\n", strerror(errno));
            abort();
        }
        got += (size_t)r;
    }
}

/* ── Per-session crypto timing ─────────────────────────────────── */
typedef struct {
    double mldsa_verify_us;
    double mlkem_encaps_us;
    double shake256_kdf_us;
    double transcript_hash_us;      /* [SECURITY-2] transcript hashing */
    double total_encrypt_us;
    double total_decrypt_us;
    uint64_t encrypt_count;
    uint64_t decrypt_count;
} crypto_timing_t;

/* ── Client state ──────────────────────────────────────────────── */
typedef struct {
    int sock;
    char name[64];

    /* [SECURITY-4] Directional keys prevent reflection attacks.
     *   key_s2c: server encrypts, client decrypts
     *   key_c2s: client encrypts, server decrypts */
    uint8_t key_s2c[KEY_LEN];      /* server→client decryption key */
    uint8_t key_c2s[KEY_LEN];      /* client→server encryption key */

    /* [SECURITY-5] Monotonic sequence numbers for nonce construction */
    uint64_t send_seq;              /* next send nonce counter */
    uint64_t recv_seq;              /* expected receive nonce counter */

    pthread_t recv_thread;
    volatile int running;
    uint64_t msgs_sent, msgs_recv;
    uint64_t bytes_sent, bytes_recv;
    double total_auth_time_ms;
    crypto_timing_t ct;
} client_t;

/* ── Wire protocol ─────────────────────────────────────────────── */
static int send_all(int sock, const void *data, size_t len) {
    uint32_t nlen = htonl(len);
    if (send(sock, &nlen, 4, MSG_NOSIGNAL) != 4) return -1;
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sock, (const uint8_t *)data + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static int recv_all(int sock, uint8_t **data, uint32_t *len) {
    uint32_t nlen;
    ssize_t r = recv(sock, &nlen, 4, MSG_WAITALL);
    if (r != 4) return -1;
    *len = ntohl(nlen);
    if (*len > 10 * 1024 * 1024) return -1;
    *data = malloc(*len);
    if (!*data) return -1;
    size_t got = 0;
    while (got < *len) {
        r = recv(sock, *data + got, *len - got, 0);
        if (r <= 0) { free(*data); *data = NULL; return -1; }
        got += r;
    }
    return 0;
}

/* ── [SECURITY-5] Monotonic nonce construction ─────────────────── */
/* Must match server's seq_to_nonce exactly */
static void seq_to_nonce(uint64_t seq, uint8_t nonce[NONCE_LEN]) {
    memset(nonce, 0, 4);
    nonce[4]  = (uint8_t)(seq      );
    nonce[5]  = (uint8_t)(seq >>  8);
    nonce[6]  = (uint8_t)(seq >> 16);
    nonce[7]  = (uint8_t)(seq >> 24);
    nonce[8]  = (uint8_t)(seq >> 32);
    nonce[9]  = (uint8_t)(seq >> 40);
    nonce[10] = (uint8_t)(seq >> 48);
    nonce[11] = (uint8_t)(seq >> 56);
}

static uint64_t nonce_to_seq(const uint8_t nonce[NONCE_LEN]) {
    uint64_t seq = 0;
    seq |= (uint64_t)nonce[4];
    seq |= (uint64_t)nonce[5]  <<  8;
    seq |= (uint64_t)nonce[6]  << 16;
    seq |= (uint64_t)nonce[7]  << 24;
    seq |= (uint64_t)nonce[8]  << 32;
    seq |= (uint64_t)nonce[9]  << 40;
    seq |= (uint64_t)nonce[10] << 48;
    seq |= (uint64_t)nonce[11] << 56;
    return seq;
}

/* ── [SECURITY-2] Transcript hash ──────────────────────────────── */
/* Must produce identical output to server's compute_transcript_hash */
static void compute_transcript_hash(
    const uint8_t *pk_sig, size_t pk_sig_len,
    const uint8_t *pk_kem, size_t pk_kem_len,
    const uint8_t *ns,     size_t ns_len,
    uint8_t hash_out[64], double *us_out)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, pk_sig, pk_sig_len);
    EVP_DigestUpdate(ctx, pk_kem, pk_kem_len);
    EVP_DigestUpdate(ctx, ns, ns_len);
    EVP_DigestFinalXOF(ctx, hash_out, 64);
    EVP_MD_CTX_free(ctx);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (us_out) *us_out = time_us(t0, t1);
}

/* ── [SECURITY-3] Transcript-bound KDF ─────────────────────────── */
/* Must produce identical output to server's derive_session_keys */
static void derive_session_keys(
    const uint8_t *ss,     size_t sslen,
    const uint8_t *pk_sig, size_t pk_sig_len,
    const uint8_t *pk_kem, size_t pk_kem_len,
    const uint8_t *ns,     size_t ns_len,
    const uint8_t *ct,     size_t ct_len,
    uint8_t key_s2c[KEY_LEN], uint8_t key_c2s[KEY_LEN],
    double *us_out)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    static const char *label = "PQ-AKE";
    uint8_t key_material[KEY_LEN * 2];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, label, strlen(label));
    EVP_DigestUpdate(ctx, ss, sslen);
    EVP_DigestUpdate(ctx, pk_sig, pk_sig_len);
    EVP_DigestUpdate(ctx, pk_kem, pk_kem_len);
    EVP_DigestUpdate(ctx, ns, ns_len);
    EVP_DigestUpdate(ctx, ct, ct_len);
    EVP_DigestFinalXOF(ctx, key_material, KEY_LEN * 2);
    EVP_MD_CTX_free(ctx);

    /* [SECURITY-4] Same split order as server:
     *   First 32 bytes = key_s2c, last 32 bytes = key_c2s */
    memcpy(key_s2c, key_material, KEY_LEN);
    memcpy(key_c2s, key_material + KEY_LEN, KEY_LEN);

    /* [SECURITY-7] Zero intermediate material */
    memset(key_material, 0, sizeof(key_material));

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (us_out) *us_out = time_us(t0, t1);
}

/* ══════════════════════════════════════════════════════════════════
 *  PRE-WARM: Eliminate cold-start penalty for ML-KEM/ML-DSA
 * ══════════════════════════════════════════════════════════════════ */

static void prewarm_pq_crypto(void) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!kem || !sig) { OQS_KEM_free(kem); OQS_SIG_free(sig); return; }

    uint8_t *pk  = malloc(kem->length_public_key);
    uint8_t *sk  = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss  = malloc(kem->length_shared_secret);
    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_decaps(kem, ss, ct, sk);

    uint8_t *spk = malloc(sig->length_public_key);
    uint8_t *ssk = malloc(sig->length_secret_key);
    uint8_t *sgn = malloc(sig->length_signature);
    size_t sl;
    OQS_SIG_keypair(sig, spk, ssk);
    OQS_SIG_sign(sig, sgn, &sl, pk, kem->length_public_key, ssk);
    OQS_SIG_verify(sig, pk, kem->length_public_key, sgn, sl, spk);

    memset(sk, 0, kem->length_secret_key);
    memset(ss, 0, kem->length_shared_secret);
    memset(ssk, 0, sig->length_secret_key);
    free(pk); free(sk); free(ct); free(ss);
    free(spk); free(ssk); free(sgn);
    OQS_KEM_free(kem);
    OQS_SIG_free(sig);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("  [prewarm] PQ crypto warmed in %.1f us (cold-start absorbed)\n",
           time_us(t0, t1));
}

/* ══════════════════════════════════════════════════════════════════
 *  AUTHENTICATION (ML-DSA verify + ML-KEM encaps)
 *
 *  CORRECTED PROTOCOL:
 *    1. C←S: sig_pk, kem_pk, ns
 *    2. C: transcript = SHAKE256(sig_pk || kem_pk || ns)  [SECURITY-2]
 *    3. C←S: signature
 *    4. C: Verify(sig_pk, transcript, signature)
 *    5. C: ct, ss = ML-KEM.Encaps(kem_pk)
 *    6. C→S: ct
 *    7. C: (key_s2c, key_c2s) = KDF(ss, sig_pk, kem_pk, ns, ct) [SECURITY-3,4]
 * ══════════════════════════════════════════════════════════════════ */

static int authenticate(client_t *c) {
    struct timespec tt0, tt1, t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &tt0);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!kem || !sig) {
        fprintf(stderr, "Failed to init PQ algorithms\n");
        if (kem) OQS_KEM_free(kem);
        if (sig) OQS_SIG_free(sig);
        return -1;
    }

    /* Receive server's DSA public key */
    uint8_t *sig_pk = NULL; uint32_t sig_pk_len;
    if (recv_all(c->sock, &sig_pk, &sig_pk_len) < 0) {
        fprintf(stderr, "Failed to receive DSA public key\n");
        OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* [SECURITY-6] Validate DSA public key length */
    if (sig_pk_len != sig->length_public_key) {
        fprintf(stderr, "  !!! REJECT: DSA pk length %u != expected %zu\n",
                sig_pk_len, sig->length_public_key);
        free(sig_pk); OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* Receive server's KEM public key */
    uint8_t *kem_pk = NULL; uint32_t kem_pk_len;
    if (recv_all(c->sock, &kem_pk, &kem_pk_len) < 0) {
        fprintf(stderr, "Failed to receive KEM public key\n");
        free(sig_pk); OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* [SECURITY-6] Validate KEM public key length */
    if (kem_pk_len != kem->length_public_key) {
        fprintf(stderr, "  !!! REJECT: KEM pk length %u != expected %zu\n",
                kem_pk_len, kem->length_public_key);
        free(sig_pk); free(kem_pk); OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* [SECURITY-1] Receive server's session nonce ns */
    uint8_t *ns = NULL; uint32_t ns_len;
    if (recv_all(c->sock, &ns, &ns_len) < 0) {
        fprintf(stderr, "Failed to receive session nonce\n");
        free(sig_pk); free(kem_pk); OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }
    if (ns_len != SESSION_NONCE_LEN) {
        fprintf(stderr, "  !!! REJECT: session nonce length %u != expected %d\n",
                ns_len, SESSION_NONCE_LEN);
        free(sig_pk); free(kem_pk); free(ns);
        OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* [SECURITY-2] Compute transcript hash: H(sig_pk || kem_pk || ns)
     * Must match server's computation exactly. */
    uint8_t transcript[64];
    compute_transcript_hash(
        sig_pk, sig_pk_len,
        kem_pk, kem_pk_len,
        ns, ns_len,
        transcript, &c->ct.transcript_hash_us);

    /* Receive signature over transcript */
    uint8_t *signature = NULL; uint32_t sl;
    if (recv_all(c->sock, &signature, &sl) < 0) {
        fprintf(stderr, "Failed to receive signature\n");
        free(sig_pk); free(kem_pk); free(ns);
        OQS_KEM_free(kem); OQS_SIG_free(sig); return -1;
    }

    /* 1. ML-DSA Signature Verification (timed)
     * [SECURITY-2] Verify against transcript hash, not just kem_pk.
     * This binds the server's identity (sig_pk), the ephemeral key (kem_pk),
     * and the session nonce (ns) together. If any component was substituted
     * by an attacker, the signature will not verify. */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_STATUS vr = OQS_SIG_verify(sig, transcript, 64, signature, sl, sig_pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->ct.mldsa_verify_us = time_us(t0, t1);

    if (vr != OQS_SUCCESS) {
        fprintf(stderr, "\n  !!! SIGNATURE VERIFICATION FAILED !!!\n");
        fprintf(stderr, "  !!! Transcript mismatch — possible MITM attack !!!\n\n");
        free(sig_pk); free(kem_pk); free(ns); free(signature);
        OQS_KEM_free(kem); OQS_SIG_free(sig);
        return -1;
    }
    printf("  [auth] ML-DSA-65 transcript verified in %.1f us\n", c->ct.mldsa_verify_us);

    /* 2. ML-KEM Encapsulation (timed) */
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_encaps(kem, ct, ss, kem_pk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->ct.mlkem_encaps_us = time_us(t0, t1);
    printf("  [auth] ML-KEM-768 encaps in %.1f us\n", c->ct.mlkem_encaps_us);

    /* Send ciphertext to server */
    send_all(c->sock, ct, kem->length_ciphertext);

    /* [SECURITY-3,4] Transcript-bound KDF with directional key split.
     * KDF input = "PQ-AKE" || ss || pk_sig || pk_kem || ns || ct
     * Output: first 32 bytes = key_s2c, last 32 bytes = key_c2s */
    derive_session_keys(
        ss, kem->length_shared_secret,
        sig_pk, sig_pk_len,
        kem_pk, kem_pk_len,
        ns, ns_len,
        ct, kem->length_ciphertext,
        c->key_s2c, c->key_c2s,
        &c->ct.shake256_kdf_us);
    printf("  [auth] SHAKE256 transcript-bound KDF in %.1f us\n", c->ct.shake256_kdf_us);
    printf("  [auth] Directional keys derived: key_s2c + key_c2s\n");

    /* [SECURITY-5] Initialize monotonic nonce counters to 0 */
    c->send_seq = 0;
    c->recv_seq = 0;

    clock_gettime(CLOCK_MONOTONIC, &tt1);
    c->total_auth_time_ms = time_us(tt0, tt1) / 1000.0;

    double crypto_ms = (c->ct.mldsa_verify_us + c->ct.mlkem_encaps_us +
                         c->ct.shake256_kdf_us + c->ct.transcript_hash_us) / 1000.0;
    printf("  [auth] Session established: total %.2f ms, crypto %.2f ms, overhead %.2f ms\n",
           c->total_auth_time_ms, crypto_ms, c->total_auth_time_ms - crypto_ms);

    /* [SECURITY-7] Zero secrets before free */
    memset(ss, 0, kem->length_shared_secret);
    memset(transcript, 0, sizeof(transcript));
    free(sig_pk); free(kem_pk); free(ns); free(signature); free(ct); free(ss);
    OQS_KEM_free(kem); OQS_SIG_free(sig);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  ENCRYPTED SEND / RECEIVE
 *  Uses directional keys and monotonic nonces.
 * ══════════════════════════════════════════════════════════════════ */

static void send_encrypted(client_t *c, const char *msg) {
    size_t ml = strlen(msg);
    uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
    uint8_t *ct = malloc(ml);

    /* [SECURITY-5] Construct nonce from monotonic counter */
    seq_to_nonce(c->send_seq, nonce);
    c->send_seq++;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    /* [SECURITY-4] Encrypt with key_c2s (client→server direction) */
    chachapoly_scalar(c->key_c2s, nonce, (const uint8_t *)msg, ct, ml, tag, 1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->ct.total_encrypt_us += time_us(t0, t1);
    c->ct.encrypt_count++;

    size_t pl = NONCE_LEN + TAG_LEN + ml;
    uint8_t *pkt = malloc(pl);
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt + NONCE_LEN, tag, TAG_LEN);
    memcpy(pkt + NONCE_LEN + TAG_LEN, ct, ml);

    if (send_all(c->sock, pkt, pl) == 0) {
        c->msgs_sent++;
        c->bytes_sent += ml;
    }
    free(ct); free(pkt);
}

static void *receiver(void *arg) {
    client_t *c = (client_t *)arg;

    while (c->running) {
        uint8_t *pkt = NULL; uint32_t pl;
        if (recv_all(c->sock, &pkt, &pl) < 0) { c->running = 0; break; }
        if (pl < NONCE_LEN + TAG_LEN) { free(pkt); continue; }

        uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
        memcpy(nonce, pkt, NONCE_LEN);
        memcpy(tag, pkt + NONCE_LEN, TAG_LEN);
        size_t ml = pl - NONCE_LEN - TAG_LEN;

        /* [SECURITY-5] Validate monotonic nonce from server.
         * Reject if the sequence number doesn't match expected counter.
         * This prevents replay and reorder attacks. */
        uint64_t received_seq = nonce_to_seq(nonce);
        if (received_seq != c->recv_seq) {
            printf("\n  [!] REJECT: nonce seq %lu != expected %lu (replay/reorder)\n",
                   (unsigned long)received_seq, (unsigned long)c->recv_seq);
            printf("  %s> ", c->name);
            fflush(stdout);
            free(pkt);
            continue;
        }
        c->recv_seq++;

        uint8_t *pt = malloc(ml + 1);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        /* [SECURITY-4] Decrypt with key_s2c (server→client direction).
         * Because key_s2c != key_c2s, an attacker cannot reflect our own
         * encrypted messages back to us. This is the core fix for Q8. */
        int rc = chachapoly_scalar(c->key_s2c, nonce,
                                    pkt + NONCE_LEN + TAG_LEN, pt, ml, tag, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (rc == 0) {
            c->ct.total_decrypt_us += time_us(t0, t1);
            c->ct.decrypt_count++;
            pt[ml] = '\0';
            printf("\n  [Server]: %s\n", pt);
            printf("  %s> ", c->name);
            fflush(stdout);
            c->msgs_recv++;
            c->bytes_recv += ml;
        } else {
            printf("\n  [!] AEAD tag verification failed\n");
            printf("  %s> ", c->name);
            fflush(stdout);
        }
        free(pt); free(pkt);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 *  PERFORMANCE SUMMARY
 * ══════════════════════════════════════════════════════════════════ */

static void print_stats(client_t *c) {
    printf("\n");
    printf("================================================================\n");
    printf("  CLIENT CRYPTOGRAPHIC PERFORMANCE SUMMARY\n");
    printf("  (Pure crypto execution time — excludes I/O)\n");
    printf("================================================================\n\n");

    double crypto_ms = (c->ct.mldsa_verify_us + c->ct.mlkem_encaps_us +
                         c->ct.shake256_kdf_us + c->ct.transcript_hash_us) / 1000.0;
    double overhead = c->total_auth_time_ms - crypto_ms;

    printf("--- AUTHENTICATION (CLIENT SIDE) -------------------------------\n");
    printf("  Total session:      %.2f ms\n", c->total_auth_time_ms);
    printf("  Pure crypto:        %.2f ms (%.1f%%)\n",
           crypto_ms, crypto_ms / c->total_auth_time_ms * 100);
    printf("  System overhead:    %.2f ms (%.1f%%)\n\n",
           overhead, overhead / c->total_auth_time_ms * 100);
    printf("  ML-DSA-65 verify:   %8.1f us\n", c->ct.mldsa_verify_us);
    printf("  ML-KEM-768 encaps:  %8.1f us\n", c->ct.mlkem_encaps_us);
    printf("  Transcript hash:    %8.1f us\n", c->ct.transcript_hash_us);
    printf("  SHAKE256 KDF:       %8.1f us\n\n", c->ct.shake256_kdf_us);

    printf("--- DATA PHASE (ChaCha20-Poly1305 scalar) ----------------------\n");
    printf("  Direction binding: key_c2s (send) / key_s2c (recv)\n");
    printf("  Nonce mode:        monotonic counter\n");
    if (c->ct.encrypt_count > 0)
        printf("  Encrypt: %lu msgs, avg %.2f us/msg (seq 0..%lu)\n",
               c->ct.encrypt_count, c->ct.total_encrypt_us / c->ct.encrypt_count,
               (unsigned long)(c->send_seq - 1));
    if (c->ct.decrypt_count > 0)
        printf("  Decrypt: %lu msgs, avg %.2f us/msg (seq 0..%lu)\n",
               c->ct.decrypt_count, c->ct.total_decrypt_us / c->ct.decrypt_count,
               (unsigned long)(c->recv_seq - 1));

    printf("\n--- MESSAGES ---------------------------------------------------\n");
    printf("  Sent: %lu (%.1f KB)  |  Received: %lu (%.1f KB)\n",
           c->msgs_sent, c->bytes_sent / 1024.0,
           c->msgs_recv, c->bytes_recv / 1024.0);

    printf("\n--- SECURITY PROPERTIES ----------------------------------------\n");
    printf("  [x] Transcript-bound verify: Verify(H(pk_sig || pk_kem || ns))\n");
    printf("  [x] Transcript-bound KDF: SHAKE256(\"PQ-AKE\" || ss || transcript)\n");
    printf("  [x] Directional keys: key_s2c != key_c2s (reflection-safe)\n");
    printf("  [x] Monotonic nonces: seq counter per direction (replay-safe)\n");
    printf("  [x] Public key + nonce length validation\n");
    printf("  [x] Secret zeroization on cleanup\n");
    printf("================================================================\n\n");
}

/* ══════════════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }

    client_t cli = {0};
    snprintf(cli.name, sizeof(cli.name), "%s", argv[1]);
    cli.running = 1;

    printf("================================================================\n");
    printf("  PQ Client: %s (SECURED)\n", cli.name);
    printf("  ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305\n");
    printf("  Transcript-bound auth | Directional keys | Monotonic nonces\n");
    printf("================================================================\n\n");

    OQS_init();

    prewarm_pq_crypto();

    cli.sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    int flag = 1;
    setsockopt(cli.sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    printf("  Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(cli.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("  connect");
        return 1;
    }
    printf("  Connected.\n\n");

    printf("--- AUTHENTICATION ---\n");
    if (authenticate(&cli) < 0) {
        close(cli.sock);
        OQS_destroy();
        return 1;
    }

    printf("\n  Session active. Type messages, 'quit' to exit.\n\n");
    pthread_create(&cli.recv_thread, NULL, receiver, &cli);

    char line[2048];
    while (cli.running) {
        printf("  %s> ", cli.name);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';
        if (!*line) continue;
        if (strcmp(line, "quit") == 0) { cli.running = 0; break; }
        send_encrypted(&cli, line);
    }

    print_stats(&cli);
    /* [SECURITY-7] Zero session keys on exit */
    memset(cli.key_s2c, 0, KEY_LEN);
    memset(cli.key_c2s, 0, KEY_LEN);
    close(cli.sock);
    OQS_destroy();
    return 0;
}
