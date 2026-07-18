/*
 * Post-Quantum Multi-Client Secure Server (CORRECTED)
 * =====================================================
 * Authentication : ML-KEM-768 + ML-DSA-65 (per-client, non-batched)
 * Data AEAD     : ChaCha20-Poly1305 with AVX2 SIMD 4-lane batching
 * KDF           : SHAKE256 (transcript-bound)
 *
 * SECURITY FIXES APPLIED:
 *   [SECURITY-1] Server session nonce ns for injective freshness
 *   [SECURITY-2] Transcript-bound signature: Sign(H(pk_sig||pk_kem||ns))
 *   [SECURITY-3] Transcript-bound KDF: SHAKE256("PQ-AKE"||ss||pk_sig||pk_kem||ns||ct)
 *   [SECURITY-4] Directional keys: key_s2c != key_c2s (prevents reflection)
 *   [SECURITY-5] Monotonic nonces with replay detection
 *   [SECURITY-6] Ciphertext length validation
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
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/random.h>

#ifndef u_int
#define u_int unsigned int
#endif

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include "chachapoly_simd.h"

/* ── Configuration ─────────────────────────────────────────────── */
#define PORT                9000
#define MAX_CLIENTS         20
#define SIMD_BATCH_SIZE     4       /* 4-lane AVX2 */
#define KEY_LEN             32
#define NONCE_LEN           12
#define TAG_LEN             16
#define BATCH_TIMEOUT_MS    500     /* flush partial batch after this */
#define SESSION_NONCE_LEN   32      /* [SECURITY-1] per-session server nonce */

/* ── Timing helper ─────────────────────────────────────────────── */
static double time_us(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1e6 + (b.tv_nsec - a.tv_nsec) / 1e3;
}

/* FIX (2026): handle getrandom partial reads and failures.
 * Old code silently ignored errors via (void)r — could leave the
 * buffer partially or fully uninitialized on EINTR/short reads.
 * For session nonces this is catastrophic. */
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

/* ── Per-client crypto timing ──────────────────────────────────── */
typedef struct {
    double mlkem_keypair_us;
    double mlkem_decaps_us;
    double mldsa_sign_us;
    double shake256_kdf_us;
    double transcript_hash_us;      /* [SECURITY-2] transcript hashing */
    double chacha_encrypt_us;
    double chacha_decrypt_us;
    uint64_t chacha_encrypt_count;
    uint64_t chacha_decrypt_count;
} crypto_timing_t;

/* ── Batch item (one queued AEAD operation) ────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   len;
    uint8_t  nonce[NONCE_LEN];
    uint8_t  tag[TAG_LEN];
    uint8_t *key;           /* pointer into client's session key */
    int      client_id;
    int      encrypt;
    uint8_t *result;
    int      done;
    int      ok;
    pthread_mutex_t *notify_lock;
    pthread_cond_t  *notify_cond;
} batch_item_t;

/* ── Batch collector ───────────────────────────────────────────── */
typedef struct {
    batch_item_t *items[SIMD_BATCH_SIZE * 4];
    int count;
    pthread_mutex_t lock;
    pthread_cond_t  ready;
} batch_queue_t;

/* ── Client session ────────────────────────────────────────────── */
typedef struct {
    int sock;
    int id;
    /* [SECURITY-4] Directional keys prevent reflection attacks.
     *   key_s2c: server encrypts, client decrypts
     *   key_c2s: client encrypts, server decrypts
     * An attacker cannot replay C→S traffic as S→C because
     * the keys are different. This is what makes ProVerif Q8
     * (injective authentication) provable. */
    uint8_t key_s2c[KEY_LEN];      /* server→client encryption key */
    uint8_t key_c2s[KEY_LEN];      /* client→server encryption key */

    /* [SECURITY-5] Monotonic sequence numbers for nonce construction.
     * Nonce = 4 zero bytes || 8-byte LE sequence number.
     * Prevents nonce reuse and enables replay detection. */
    uint64_t send_seq;              /* next send nonce counter */
    uint64_t recv_seq;              /* expected receive nonce counter */

    int active;
    char name[64];
    pthread_t thread;

    uint64_t msgs_sent;
    uint64_t msgs_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;

    double total_auth_time_ms;
    crypto_timing_t crypto_times;
    struct timespec session_start;
} client_t;

/* ── Server state ──────────────────────────────────────────────── */
typedef struct {
    client_t clients[MAX_CLIENTS];
    int num_clients;
    pthread_mutex_t clients_lock;

    OQS_SIG *sig;
    uint8_t *sig_pk;
    uint8_t *sig_sk;

    batch_queue_t queue;
    pthread_t batch_thread;

    uint64_t simd_batches;
    uint64_t simd_messages;
    double   simd_total_us;
    double   scalar_total_us;
    uint64_t scalar_messages;
    double   direct_encrypt_total_us;
    uint64_t direct_encrypt_count;

    volatile int running;
} server_t;

static server_t srv = {0};

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
    if (*len > 10*1024*1024) return -1;
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
/* Nonce = 4 zero bytes || 8-byte LE counter.
 * This ensures nonces are never reused under the same key,
 * which is critical for ChaCha20-Poly1305 security.
 * The 4-byte prefix is zero; the suffix encodes the counter.
 * With directional keys, each direction has its own counter space. */
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

/* Parse nonce back to sequence number (for replay detection) */
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
/* H = SHAKE256(pk_sig || pk_kem || ns), output 64 bytes.
 * This is the message that gets signed by ML-DSA, binding the
 * server's identity (pk_sig), the ephemeral KEM key (pk_kem),
 * and the session nonce (ns) into a single signed commitment.
 * Signing the hash rather than pk_kem alone prevents an attacker
 * from replaying a signature from a different session. */
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
/* key_material = SHAKE256("PQ-AKE" || ss || pk_sig || pk_kem || ns || ct)
 * Output: 64 bytes → split into key_s2c (first 32) and key_c2s (last 32).
 *
 * Binding all handshake values into the KDF prevents:
 *   - Cross-session key confusion (ns is unique per session)
 *   - Identity misbinding (pk_sig bound)
 *   - KEM public key substitution (pk_kem bound)
 *   - Ciphertext replacement (ct bound) */
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

    /* [SECURITY-4] First 32 bytes = server→client key,
     *              Last  32 bytes = client→server key */
    memcpy(key_s2c, key_material, KEY_LEN);
    memcpy(key_c2s, key_material + KEY_LEN, KEY_LEN);

    /* [SECURITY-7] Zero intermediate material */
    memset(key_material, 0, sizeof(key_material));

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (us_out) *us_out = time_us(t0, t1);
}

/* ══════════════════════════════════════════════════════════════════
 *  BATCH PROCESSOR THREAD — ADAPTIVE (2026 revision)
 *
 *  Groups queued items by size class (64-byte buckets), then:
 *    - 4 items in same class  → AVX2 batch (full lanes utilized)
 *    - 1-3 items in a class   → scalar (avoids 0.83× regime
 *                                       documented in §V-F)
 *
 *  This addresses the paper's observation that partial-batch or
 *  mixed-length workloads under-perform scalar. Scheduling around
 *  the size class gives the SIMD path only full-lane work.
 * ══════════════════════════════════════════════════════════════════ */

#define SIZE_CLASS_SHIFT  6   /* 64-byte buckets */
#define MAX_SIZE_CLASSES  16

static inline int size_class(size_t len) {
    int c = (int)((len + 63) >> SIZE_CLASS_SHIFT);
    if (c >= MAX_SIZE_CLASSES) c = MAX_SIZE_CLASSES - 1;
    return c;
}

/* Statistics for adaptive scheduler report */
static uint64_t adaptive_full_batches  = 0;
static uint64_t adaptive_full_msgs     = 0;
static uint64_t adaptive_scalar_msgs   = 0;
static double   adaptive_simd_us       = 0;
static double   adaptive_scalar_us     = 0;

static void deliver_result(batch_item_t *it, uint8_t *out, int rc) {
    it->result = out;
    it->ok     = (rc == 0) ? 0 : -1;
    it->done   = 1;
    pthread_mutex_lock(it->notify_lock);
    pthread_cond_signal(it->notify_cond);
    pthread_mutex_unlock(it->notify_lock);
}

static void process_batch(batch_item_t **items, int count) {
    if (count == 0) return;
    int is_encrypt = items[0]->encrypt;

    /* Group items by size class. */
    int class_items[MAX_SIZE_CLASSES][4];
    int class_count[MAX_SIZE_CLASSES] = {0};

    for (int i = 0; i < count; i++) {
        int c = size_class(items[i]->len);
        if (class_count[c] < 4)
            class_items[c][class_count[c]++] = i;
    }

    /* Process each size class. */
    for (int c = 0; c < MAX_SIZE_CLASSES; c++) {
        int n = class_count[c];
        if (n == 0) continue;

        if (n == 4) {
            /* ── AVX2 batch path ── */
            const uint8_t *keys[4], *nonces[4], *inputs[4];
            uint8_t *outputs[4], *tags[4];
            size_t lengths[4];

            for (int j = 0; j < 4; j++) {
                batch_item_t *it = items[class_items[c][j]];
                keys[j]    = it->key;
                nonces[j]  = it->nonce;
                inputs[j]  = it->data;
                lengths[j] = it->len;
                tags[j]    = it->tag;
                outputs[j] = malloc(it->len);
                if (!outputs[j]) {
                    fprintf(stderr, "process_batch: OOM\n");
                    for (int k = 0; k < j; k++) free(outputs[k]);
                    return;
                }
            }

            struct timespec tb0, tb1;
            clock_gettime(CLOCK_MONOTONIC, &tb0);
            int rc = chachapoly_batch4_avx2(keys, nonces, inputs, outputs,
                                             lengths, tags, is_encrypt);
            clock_gettime(CLOCK_MONOTONIC, &tb1);

            double dt = time_us(tb0, tb1);
            adaptive_simd_us += dt;
            adaptive_full_batches++;
            adaptive_full_msgs += 4;
            srv.simd_batches++;
            srv.simd_messages += 4;
            srv.simd_total_us += dt;

            for (int j = 0; j < 4; j++)
                deliver_result(items[class_items[c][j]], outputs[j], rc);
        } else {
            /* ── Scalar fallback ── */
            for (int j = 0; j < n; j++) {
                batch_item_t *it = items[class_items[c][j]];
                uint8_t *out = malloc(it->len);
                if (!out) {
                    fprintf(stderr, "process_batch: OOM in scalar fallback\n");
                    deliver_result(it, NULL, -1);
                    continue;
                }

                struct timespec ts0, ts1;
                clock_gettime(CLOCK_MONOTONIC, &ts0);
                int rc = chachapoly_scalar(it->key, it->nonce, it->data,
                                            out, it->len, it->tag, is_encrypt);
                clock_gettime(CLOCK_MONOTONIC, &ts1);

                double dt = time_us(ts0, ts1);
                adaptive_scalar_us += dt;
                adaptive_scalar_msgs++;
                srv.scalar_total_us += dt;
                srv.scalar_messages++;

                deliver_result(it, out, rc);
            }
        }
    }
}

static void *batch_thread_fn(void *arg) {
    (void)arg;
    while (srv.running) {
        pthread_mutex_lock(&srv.queue.lock);

        while (srv.queue.count < SIMD_BATCH_SIZE && srv.running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += BATCH_TIMEOUT_MS * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec  += ts.tv_nsec / 1000000000L;
                ts.tv_nsec %= 1000000000L;
            }
            int rc = pthread_cond_timedwait(&srv.queue.ready, &srv.queue.lock, &ts);
            if (rc == ETIMEDOUT && srv.queue.count > 0) break;
        }

        if (srv.queue.count == 0) {
            pthread_mutex_unlock(&srv.queue.lock);
            continue;
        }

        int n = (srv.queue.count > SIMD_BATCH_SIZE) ? SIMD_BATCH_SIZE : srv.queue.count;
        batch_item_t *work[SIMD_BATCH_SIZE];
        for (int i = 0; i < n; i++)
            work[i] = srv.queue.items[i];

        int remain = srv.queue.count - n;
        for (int i = 0; i < remain; i++)
            srv.queue.items[i] = srv.queue.items[n + i];
        srv.queue.count = remain;

        pthread_mutex_unlock(&srv.queue.lock);

        process_batch(work, n);
    }
    return NULL;
}

static int submit_to_batch(batch_item_t *item) {
    pthread_mutex_t  mtx = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t   cnd = PTHREAD_COND_INITIALIZER;
    item->notify_lock = &mtx;
    item->notify_cond = &cnd;
    item->done = 0;

    pthread_mutex_lock(&srv.queue.lock);
    if (srv.queue.count < SIMD_BATCH_SIZE * 4) {
        srv.queue.items[srv.queue.count++] = item;
        if (srv.queue.count >= SIMD_BATCH_SIZE)
            pthread_cond_signal(&srv.queue.ready);
    }
    pthread_mutex_unlock(&srv.queue.lock);

    pthread_mutex_lock(&mtx);
    while (!item->done)
        pthread_cond_wait(&cnd, &mtx);
    pthread_mutex_unlock(&mtx);

    pthread_mutex_destroy(&mtx);
    pthread_cond_destroy(&cnd);
    return item->ok;
}

/* ══════════════════════════════════════════════════════════════════
 *  AUTHENTICATION (per-client, non-batched)
 *
 *  CORRECTED PROTOCOL:
 *    1. S: Generate kem_pk, kem_sk = ML-KEM.Keygen()
 *    2. S: Generate ns = random(32)           [SECURITY-1]
 *    3. S→C: sig_pk, kem_pk, ns
 *    4. S: transcript = SHAKE256(sig_pk || kem_pk || ns)  [SECURITY-2]
 *    5. S: signature = ML-DSA.Sign(sig_sk, transcript)
 *    6. S→C: signature
 *    7. C→S: ct (ML-KEM ciphertext)
 *    8. S: ss = ML-KEM.Decaps(kem_sk, ct)
 *    9. S: (key_s2c, key_c2s) = KDF(ss, sig_pk, kem_pk, ns, ct) [SECURITY-3,4]
 * ══════════════════════════════════════════════════════════════════ */

static int authenticate_client(client_t *c, OQS_KEM *kem) {
    struct timespec t_total0, t_total1, t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t_total0);

    /* 1. ML-KEM keypair generation (timed) */
    uint8_t *kem_pk = malloc(kem->length_public_key);
    uint8_t *kem_sk = malloc(kem->length_secret_key);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_keypair(kem, kem_pk, kem_sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->crypto_times.mlkem_keypair_us = time_us(t0, t1);

    /* [SECURITY-1] Generate fresh session nonce ns.
     * This 32-byte random value is unique per session and gets bound
     * into both the signature and the KDF, ensuring each session has
     * a unique cryptographic identity. This is what makes the
     * injective correspondence in ProVerif (Q8) provable:
     * different ns → different transcript → different signature →
     * each ClientAcceptsServer maps to exactly one ServerDerivesKey. */
    uint8_t ns[SESSION_NONCE_LEN];
    rand_bytes(ns, SESSION_NONCE_LEN);

    /* Send: sig_pk, kem_pk, ns (network I/O excluded from crypto timing) */
    if (send_all(c->sock, srv.sig_pk, srv.sig->length_public_key) < 0 ||
        send_all(c->sock, kem_pk, kem->length_public_key) < 0 ||
        send_all(c->sock, ns, SESSION_NONCE_LEN) < 0) {
        free(kem_pk); free(kem_sk); return -1;
    }

    /* [SECURITY-2] Compute transcript hash: H(sig_pk || kem_pk || ns)
     * Signing the hash of the full transcript rather than just kem_pk
     * binds the server's long-term identity and the session nonce
     * into the signature. */
    uint8_t transcript[64];
    compute_transcript_hash(
        srv.sig_pk, srv.sig->length_public_key,
        kem_pk, kem->length_public_key,
        ns, SESSION_NONCE_LEN,
        transcript, &c->crypto_times.transcript_hash_us);

    /* 2. ML-DSA sign the transcript (timed) */
    uint8_t *signature = malloc(srv.sig->length_signature);
    size_t sig_len;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_SIG_sign(srv.sig, signature, &sig_len,
                  transcript, 64, srv.sig_sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->crypto_times.mldsa_sign_us = time_us(t0, t1);

    if (send_all(c->sock, signature, sig_len) < 0) {
        free(kem_pk); free(kem_sk); free(signature); return -1;
    }

    /* Receive ML-KEM ciphertext from client */
    uint8_t *ct = NULL;
    uint32_t ct_len;
    if (recv_all(c->sock, &ct, &ct_len) < 0) {
        free(kem_pk); free(kem_sk); free(signature); return -1;
    }

    /* [SECURITY-6] Validate ciphertext length.
     * Reject immediately if the ciphertext is not the expected size
     * for ML-KEM-768. An incorrect length indicates either corruption
     * or an active attack attempting to exploit decapsulation edge cases. */
    if (ct_len != kem->length_ciphertext) {
        fprintf(stderr, "[Client %d] REJECT: ciphertext length %u != expected %zu\n",
                c->id, ct_len, kem->length_ciphertext);
        free(kem_pk); free(kem_sk); free(signature); free(ct);
        return -1;
    }

    /* 3. ML-KEM decapsulation (timed) */
    uint8_t *ss = malloc(kem->length_shared_secret);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    OQS_KEM_decaps(kem, ss, ct, kem_sk);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    c->crypto_times.mlkem_decaps_us = time_us(t0, t1);

    /* [SECURITY-3,4] Transcript-bound KDF with directional key split.
     * KDF input = "PQ-AKE" || ss || pk_sig || pk_kem || ns || ct
     * Output: first 32 bytes = key_s2c, last 32 bytes = key_c2s */
    derive_session_keys(
        ss, kem->length_shared_secret,
        srv.sig_pk, srv.sig->length_public_key,
        kem_pk, kem->length_public_key,
        ns, SESSION_NONCE_LEN,
        ct, ct_len,
        c->key_s2c, c->key_c2s,
        &c->crypto_times.shake256_kdf_us);

    /* [SECURITY-5] Initialize monotonic nonce counters to 0 */
    c->send_seq = 0;
    c->recv_seq = 0;

    clock_gettime(CLOCK_MONOTONIC, &t_total1);
    c->total_auth_time_ms = time_us(t_total0, t_total1) / 1000.0;

    /* [SECURITY-7] Zero secrets before free */
    memset(kem_sk, 0, kem->length_secret_key);
    memset(ss, 0, kem->length_shared_secret);
    memset(transcript, 0, sizeof(transcript));
    free(kem_pk); free(kem_sk); free(signature); free(ct); free(ss);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  SEND TO CLIENT (direct scalar encrypt for server-initiated msgs)
 *  Uses key_s2c and monotonic nonce counter.
 * ══════════════════════════════════════════════════════════════════ */

static void send_to_client(client_t *c, const char *msg) {
    if (!c->active) return;

    size_t msg_len = strlen(msg);
    uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
    uint8_t *ct = malloc(msg_len);

    /* [SECURITY-5] Construct nonce from monotonic counter.
     * Each call increments the counter, guaranteeing nonce uniqueness
     * under key_s2c. */
    seq_to_nonce(c->send_seq, nonce);
    c->send_seq++;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    /* [SECURITY-4] Encrypt with key_s2c (server→client direction) */
    chachapoly_scalar(c->key_s2c, nonce, (const uint8_t *)msg, ct, msg_len, tag, 1);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double enc_us = time_us(t0, t1);
    c->crypto_times.chacha_encrypt_us += enc_us;
    c->crypto_times.chacha_encrypt_count++;
    srv.direct_encrypt_total_us += enc_us;
    srv.direct_encrypt_count++;

    size_t pkt_len = NONCE_LEN + TAG_LEN + msg_len;
    uint8_t *pkt = malloc(pkt_len);
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt + NONCE_LEN, tag, TAG_LEN);
    memcpy(pkt + NONCE_LEN + TAG_LEN, ct, msg_len);

    if (send_all(c->sock, pkt, pkt_len) == 0) {
        c->msgs_sent++;
        c->bytes_sent += msg_len;
    }
    free(ct);
    free(pkt);
}

static void broadcast_message(const char *msg) {
    pthread_mutex_lock(&srv.clients_lock);
    int sent = 0;
    for (int i = 0; i < srv.num_clients; i++) {
        if (srv.clients[i].active) {
            send_to_client(&srv.clients[i], msg);
            sent++;
        }
    }
    pthread_mutex_unlock(&srv.clients_lock);
    printf("[Server] Broadcast to %d clients\n", sent);
}

/* ══════════════════════════════════════════════════════════════════
 *  CLIENT HANDLER THREAD
 * ══════════════════════════════════════════════════════════════════ */

static void *client_handler(void *arg) {
    client_t *c = (client_t *)arg;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { c->active = 0; close(c->sock); return NULL; }

    if (authenticate_client(c, kem) < 0) {
        fprintf(stderr, "[Client %d] Authentication failed\n", c->id);
        close(c->sock);
        c->active = 0;
        OQS_KEM_free(kem);
        return NULL;
    }

    printf("[Client %d '%s'] Authenticated (total %.2f ms, crypto-only %.2f ms)\n",
           c->id, c->name, c->total_auth_time_ms,
           (c->crypto_times.mlkem_keypair_us + c->crypto_times.mlkem_decaps_us +
            c->crypto_times.mldsa_sign_us + c->crypto_times.shake256_kdf_us +
            c->crypto_times.transcript_hash_us) / 1000.0);
    printf("  ML-KEM keypair: %.1f us | ML-DSA sign: %.1f us | ML-KEM decaps: %.1f us\n",
           c->crypto_times.mlkem_keypair_us, c->crypto_times.mldsa_sign_us,
           c->crypto_times.mlkem_decaps_us);
    printf("  Transcript hash: %.1f us | KDF: %.1f us\n",
           c->crypto_times.transcript_hash_us, c->crypto_times.shake256_kdf_us);

    clock_gettime(CLOCK_MONOTONIC, &c->session_start);

    /* Persistent receive loop */
    while (c->active && srv.running) {
        uint8_t *pkt = NULL;
        uint32_t pkt_len;
        if (recv_all(c->sock, &pkt, &pkt_len) < 0) break;
        if (pkt_len < NONCE_LEN + TAG_LEN) { free(pkt); continue; }

        size_t ct_len = pkt_len - NONCE_LEN - TAG_LEN;

        /* [SECURITY-5] Validate monotonic nonce from client.
         * Extract the sequence number from the received nonce and
         * verify it matches our expected counter. This prevents
         * replay attacks and ensures ordering. */
        uint64_t received_seq = nonce_to_seq(pkt);
        if (received_seq != c->recv_seq) {
            printf("[Client %d] REJECT: nonce seq %lu != expected %lu (replay/reorder)\n",
                   c->id, (unsigned long)received_seq, (unsigned long)c->recv_seq);
            free(pkt);
            continue;
        }
        c->recv_seq++;

        /* Build batch item */
        batch_item_t item;
        memset(&item, 0, sizeof(item));
        item.encrypt   = 0;
        memcpy(item.nonce, pkt, NONCE_LEN);
        memcpy(item.tag, pkt + NONCE_LEN, TAG_LEN);
        item.len  = ct_len;
        item.data = malloc(ct_len);
        memcpy(item.data, pkt + NONCE_LEN + TAG_LEN, ct_len);
        /* [SECURITY-4] Decrypt with key_c2s (client→server direction) */
        item.key  = c->key_c2s;
        item.client_id = c->id;
        free(pkt);

        /* Submit to SIMD batch queue and wait */
        int rc = submit_to_batch(&item);

        if (rc == 0 && item.result) {
            char *pt = malloc(ct_len + 1);
            memcpy(pt, item.result, ct_len);
            pt[ct_len] = '\0';
            printf("[Client %d '%s']: %s\n", c->id, c->name, pt);
            free(pt);

            c->msgs_recv++;
            c->bytes_recv += ct_len;
            c->crypto_times.chacha_decrypt_count++;
        } else {
            printf("[Client %d] AEAD tag verification failed!\n", c->id);
        }

        free(item.data);
        free(item.result);
    }

    printf("[Client %d '%s'] Disconnected\n", c->id, c->name);
    close(c->sock);
    c->active = 0;
    /* [SECURITY-7] Zero session keys on disconnect */
    memset(c->key_s2c, 0, KEY_LEN);
    memset(c->key_c2s, 0, KEY_LEN);
    OQS_KEM_free(kem);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 *  SERVER COMMANDS
 * ══════════════════════════════════════════════════════════════════ */

static void *input_handler(void *arg) {
    (void)arg;
    char line[2048];

    printf("\n");
    printf("  Commands: list | send <id> <msg> | broadcast <msg> | bench | quit\n\n");

    while (srv.running) {
        printf("server> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';
        if (!*line) continue;

        if (strcmp(line, "quit") == 0) {
            srv.running = 0;
            break;
        }
        if (strcmp(line, "list") == 0) {
            pthread_mutex_lock(&srv.clients_lock);
            printf("\n  Active sessions:\n");
            for (int i = 0; i < srv.num_clients; i++) {
                if (srv.clients[i].active)
                    printf("    [%d] %-12s sent=%lu recv=%lu seq_s=%lu seq_r=%lu\n",
                           srv.clients[i].id, srv.clients[i].name,
                           srv.clients[i].msgs_sent, srv.clients[i].msgs_recv,
                           (unsigned long)srv.clients[i].send_seq,
                           (unsigned long)srv.clients[i].recv_seq);
            }
            printf("\n");
            pthread_mutex_unlock(&srv.clients_lock);
            continue;
        }
        if (strncmp(line, "send ", 5) == 0) {
            int id; char msg[2048];
            if (sscanf(line + 5, "%d %[^\n]", &id, msg) == 2) {
                pthread_mutex_lock(&srv.clients_lock);
                if (id > 0 && id <= srv.num_clients && srv.clients[id-1].active) {
                    send_to_client(&srv.clients[id-1], msg);
                    printf("  -> sent to client %d\n", id);
                } else {
                    printf("  client %d not found\n", id);
                }
                pthread_mutex_unlock(&srv.clients_lock);
            }
            continue;
        }
        if (strncmp(line, "broadcast ", 10) == 0) {
            broadcast_message(line + 10);
            continue;
        }
        if (strcmp(line, "bench") == 0) {
            printf("\n  Running ChaCha20-Poly1305 benchmark (1000 iterations)...\n");
            uint8_t k0[32], k1[32], k2[32], k3[32];
            uint8_t n0[12], n1[12], n2[12], n3[12];
            rand_bytes(k0,32); rand_bytes(k1,32); rand_bytes(k2,32); rand_bytes(k3,32);
            rand_bytes(n0,12); rand_bytes(n1,12); rand_bytes(n2,12); rand_bytes(n3,12);

            uint8_t pt[256]; rand_bytes(pt, 256);
            uint8_t ct0[256],ct1[256],ct2[256],ct3[256];
            uint8_t tg0[16],tg1[16],tg2[16],tg3[16];

            const uint8_t *ks[4] = {k0,k1,k2,k3};
            const uint8_t *ns_arr[4] = {n0,n1,n2,n3};
            const uint8_t *ins[4] = {pt,pt,pt,pt};
            uint8_t *outs[4] = {ct0,ct1,ct2,ct3};
            uint8_t *tgs[4] = {tg0,tg1,tg2,tg3};
            size_t lens[4] = {256,256,256,256};

            struct timespec t0_b,t1_b;
            clock_gettime(CLOCK_MONOTONIC, &t0_b);
            for (int i = 0; i < 1000; i++) {
                for (int j = 0; j < 4; j++)
                    chachapoly_scalar(ks[j],ns_arr[j],pt,outs[j],256,tgs[j],1);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1_b);
            double seq = time_us(t0_b,t1_b);

            clock_gettime(CLOCK_MONOTONIC, &t0_b);
            for (int i = 0; i < 1000; i++)
                chachapoly_batch4_avx2(ks,ns_arr,ins,outs,lens,tgs,1);
            clock_gettime(CLOCK_MONOTONIC, &t1_b);
            double bat = time_us(t0_b,t1_b);

            printf("  Sequential (4x1000): %.2f ms\n", seq/1000);
            printf("  AVX2 batch (1000):   %.2f ms\n", bat/1000);
            printf("  Speedup:             %.2fx\n\n", seq/bat);
            continue;
        }
        printf("  Unknown command. Try: list | send | broadcast | bench | quit\n");
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 *  FINAL PERFORMANCE REPORT
 * ══════════════════════════════════════════════════════════════════ */

static void print_report(void) {
    printf("\n");
    printf("================================================================\n");
    printf("  CRYPTOGRAPHIC PERFORMANCE REPORT\n");
    printf("  (Pure crypto execution time — excludes I/O, threading, alloc)\n");
    printf("================================================================\n\n");

    printf("--- PHASE 1: PER-CLIENT AUTHENTICATION (SERVER SIDE) -----------\n");
    printf("  Protocol: ML-KEM-768 + ML-DSA-65 + SHAKE256\n");
    printf("  Security: Transcript-bound sig + directional keys + session nonce\n");
    printf("  Note: ML-KEM uses liboqs AVX2-optimized NTT internally\n");
    printf("  Clients authenticated: %d\n\n", srv.num_clients);

    double sum_keygen=0, sum_decaps=0, sum_sign=0, sum_kdf=0, sum_total=0, sum_thash=0;
    int valid = 0;

    printf("  Client | Total(ms) | KEM-Gen(us) | KEM-Dec(us) | DSA-Sign(us) | THash(us) | KDF(us)\n");
    printf("  -------|-----------|-------------|-------------|--------------|-----------|--------\n");

    for (int i = 0; i < srv.num_clients; i++) {
        client_t *c = &srv.clients[i];
        if (c->total_auth_time_ms <= 0) continue;
        printf("    %2d   | %7.2f   | %9.1f   | %9.1f   | %10.1f   | %7.1f   | %6.1f\n",
               c->id, c->total_auth_time_ms,
               c->crypto_times.mlkem_keypair_us, c->crypto_times.mlkem_decaps_us,
               c->crypto_times.mldsa_sign_us, c->crypto_times.transcript_hash_us,
               c->crypto_times.shake256_kdf_us);
        sum_keygen += c->crypto_times.mlkem_keypair_us;
        sum_decaps += c->crypto_times.mlkem_decaps_us;
        sum_sign   += c->crypto_times.mldsa_sign_us;
        sum_thash  += c->crypto_times.transcript_hash_us;
        sum_kdf    += c->crypto_times.shake256_kdf_us;
        sum_total  += c->total_auth_time_ms;
        valid++;
    }

    if (valid > 0) {
        double avg_crypto = (sum_keygen+sum_decaps+sum_sign+sum_thash+sum_kdf) / valid / 1000.0;
        printf("\n  Averages (%d clients):\n", valid);
        printf("    Total session: %.2f ms  |  Pure crypto: %.2f ms\n",
               sum_total/valid, avg_crypto);
        printf("    ML-KEM keygen: %.1f us  |  ML-KEM decaps: %.1f us\n",
               sum_keygen/valid, sum_decaps/valid);
        printf("    ML-DSA sign:   %.1f us  |  Transcript hash: %.1f us\n",
               sum_sign/valid, sum_thash/valid);
        printf("    SHAKE256 KDF:  %.1f us\n\n", sum_kdf/valid);
    }

    printf("--- PHASE 2: SYMMETRIC AEAD (ChaCha20-Poly1305) ---------------\n\n");

    if (srv.direct_encrypt_count > 0) {
        printf("  SERVER -> CLIENT (direct scalar, key_s2c, monotonic nonce):\n");
        printf("    Operations:  %lu\n", srv.direct_encrypt_count);
        printf("    Total time:  %.2f ms\n", srv.direct_encrypt_total_us / 1000);
        printf("    Per-message: %.2f us\n\n",
               srv.direct_encrypt_total_us / srv.direct_encrypt_count);
    }

    if (srv.simd_batches > 0) {
        double avg_simd_per_batch = srv.simd_total_us / srv.simd_batches;
        double avg_simd_per_msg   = avg_simd_per_batch / SIMD_BATCH_SIZE;
        
        printf("  CLIENT -> SERVER (SIMD batch, key_c2s, monotonic nonce):\n");
        printf("    Batch size:       %d (AVX2 4-lane)\n", SIMD_BATCH_SIZE);
        printf("    Total batches:    %lu\n", srv.simd_batches);
        printf("    Total messages:   %lu\n", srv.simd_messages);
        printf("\n");
        printf("    AVX2 SIMD:        %.2f us/batch  (%.2f us/msg)\n",
               avg_simd_per_batch, avg_simd_per_msg);
        printf("    (Scalar baseline measured separately; run 'make validate'\n");
        printf("     for per-size microbenchmark numbers in test_simd.)\n\n");
    } 
         else {
        printf("  No SIMD batches processed (need client messages).\n\n");
    }

    printf("--- MESSAGE STATISTICS -----------------------------------------\n");
    for (int i = 0; i < srv.num_clients; i++) {
        client_t *c = &srv.clients[i];
        if (c->total_auth_time_ms > 0)
            printf("  [%d] %-12s  sent=%lu  recv=%lu  (%.1f KB / %.1f KB)\n",
                   c->id, c->name, c->msgs_sent, c->msgs_recv,
                   c->bytes_sent/1024.0, c->bytes_recv/1024.0);
    }

    /* ── Adaptive scheduler report (2026 addition) ─────────────── */
    printf("\n--- ADAPTIVE BATCH SCHEDULER -----------------------------------\n");
    uint64_t total = adaptive_full_msgs + adaptive_scalar_msgs;
    if (total > 0) {
        double full_pct = 100.0 * adaptive_full_msgs / total;
        printf("  Total messages:        %lu\n", total);
        printf("  Full AVX2 batches:     %lu (%.1f%% of messages)\n",
               adaptive_full_batches, full_pct);
        printf("  Scalar fallback:       %lu (%.1f%% of messages)\n",
               adaptive_scalar_msgs, 100.0 - full_pct);
        if (adaptive_full_batches > 0)
            printf("  Avg AVX2 per-batch:    %.2f us  (%.2f us/msg)\n",
                   adaptive_simd_us / adaptive_full_batches,
                   adaptive_simd_us / (adaptive_full_batches * 4));
        if (adaptive_scalar_msgs > 0)
            printf("  Avg scalar per-msg:    %.2f us\n",
                   adaptive_scalar_us / adaptive_scalar_msgs);
        printf("  Note: scheduler routes partial-batch work to scalar to\n"
               "        avoid the 0.83x under-batched regime.\n");
    } else {
        printf("  No batched messages yet.\n");
    }

    printf("\n--- SECURITY PROPERTIES ----------------------------------------\n");
    printf("  [x] Transcript-bound signature: Sign(H(pk_sig || pk_kem || ns))\n");
    printf("  [x] Transcript-bound KDF: SHAKE256(\"PQ-AKE\" || ss || transcript)\n");
    printf("  [x] Directional keys: key_s2c != key_c2s (reflection-safe)\n");
    printf("  [x] Monotonic nonces: seq counter per direction (replay-safe)\n");
    printf("  [x] Ciphertext length validation\n");
    printf("  [x] Secret zeroization on cleanup\n");
    printf("\n--- IMPLEMENTATION NOTES ---------------------------------------\n");
    printf("  [x] ML-KEM-768: liboqs with AVX2-optimized NTT/poly ops\n");
    printf("  [x] ML-DSA-65:  liboqs with AVX2 internal optimization\n");
    printf("  [x] ChaCha20:   Real AVX2 4-lane parallel keystream gen\n");
    printf("  [x] Poly1305:   Scalar (per-stream)\n");
    printf("  [x] Batching:   Applied to symmetric AEAD only (not PQ)\n");
    printf("  [x] Speedup:    Measured on identical data, scalar vs AVX2\n");
    printf("================================================================\n\n");
}

/* ══════════════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════════════ */

static void sigint_handler(int sig) { (void)sig; srv.running = 0; }

int main(void) {
    printf("================================================================\n");
    printf("  Post-Quantum Multi-Client Server (SECURED)\n");
    printf("  ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 (AVX2 SIMD)\n");
    printf("  Transcript-bound auth | Directional keys | Monotonic nonces\n");
    printf("================================================================\n\n");

    signal(SIGINT, sigint_handler);
    srv.running = 1;

    if (chachapoly_simd_available()) {
        printf("[+] AVX2 SIMD available — batch AEAD enabled\n");
    } else {
        printf("[!] AVX2 not available — falling back to scalar\n");
    }

    pthread_mutex_init(&srv.clients_lock, NULL);
    pthread_mutex_init(&srv.queue.lock, NULL);
    pthread_cond_init(&srv.queue.ready, NULL);

    OQS_init();
    srv.sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!srv.sig) { fprintf(stderr, "Failed to init ML-DSA-65\n"); return 1; }
    srv.sig_pk = malloc(srv.sig->length_public_key);
    srv.sig_sk = malloc(srv.sig->length_secret_key);
    OQS_SIG_keypair(srv.sig, srv.sig_pk, srv.sig_sk);
    printf("[+] ML-DSA-65 signing keypair generated (%zu byte pk)\n",
           srv.sig->length_public_key);

    /* Pre-warm ML-KEM AVX2 codepath */
    {
        struct timespec tw0, tw1;
        clock_gettime(CLOCK_MONOTONIC, &tw0);
        OQS_KEM *wkem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        uint8_t *wpk = malloc(wkem->length_public_key);
        uint8_t *wsk = malloc(wkem->length_secret_key);
        uint8_t *wct = malloc(wkem->length_ciphertext);
        uint8_t *wss = malloc(wkem->length_shared_secret);
        OQS_KEM_keypair(wkem, wpk, wsk);
        OQS_KEM_encaps(wkem, wct, wss, wpk);
        OQS_KEM_decaps(wkem, wss, wct, wsk);
        memset(wsk, 0, wkem->length_secret_key);
        memset(wss, 0, wkem->length_shared_secret);
        free(wpk); free(wsk); free(wct); free(wss);
        OQS_KEM_free(wkem);
        clock_gettime(CLOCK_MONOTONIC, &tw1);
        printf("[+] ML-KEM AVX2 pre-warmed in %.1f us\n", time_us(tw0, tw1));
    }

    pthread_create(&srv.batch_thread, NULL, batch_thread_fn, NULL);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(server_sock, MAX_CLIENTS);
    printf("[+] Listening on port %d\n\n", PORT);

    pthread_t input_thread;
    pthread_create(&input_thread, NULL, input_handler, NULL);

    while (srv.running && srv.num_clients < MAX_CLIENTS) {
        int csock = accept(server_sock, NULL, NULL);
        if (csock < 0) { if (errno == EINTR) continue; continue; }

        int flag = 1;
        setsockopt(csock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        pthread_mutex_lock(&srv.clients_lock);
        client_t *c = &srv.clients[srv.num_clients];
        memset(c, 0, sizeof(*c));
        c->sock = csock;
        c->id = srv.num_clients + 1;
        c->active = 1;
        snprintf(c->name, sizeof(c->name), "Client%d", c->id);
        printf("[+] Client %d connected\n", c->id);
        pthread_create(&c->thread, NULL, client_handler, c);
        pthread_detach(c->thread);
        srv.num_clients++;
        pthread_mutex_unlock(&srv.clients_lock);
    }

    pthread_join(input_thread, NULL);
    sleep(1);

    pthread_mutex_lock(&srv.queue.lock);
    pthread_cond_signal(&srv.queue.ready);
    pthread_mutex_unlock(&srv.queue.lock);
    pthread_join(srv.batch_thread, NULL);

    print_report();

    close(server_sock);
    /* [SECURITY-7] Zero long-term signing key */
    memset(srv.sig_sk, 0, srv.sig->length_secret_key);
    free(srv.sig_pk); free(srv.sig_sk);
    OQS_SIG_free(srv.sig);
    OQS_destroy();
    return 0;
}
