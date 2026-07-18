# Post-Quantum Authenticated Key Exchange with SIMD AEAD

Implementation accompanying the paper:
"A Formally Verified Post-Quantum Authenticated Key Exchange with
 System-Level AEAD Evaluation"

## Components
- server.c, client.c: PQ-AKE protocol (ML-KEM-768 + ML-DSA-65)
- chacha20_avx2.h, chachapoly_simd.{c,h}: AVX2 4-lane ChaCha20-Poly1305
- test_simd.c: RFC 8439 validation + AVX2/scalar consistency tests

## Building
Requires liboqs 0.10.x, OpenSSL, gcc with AVX2 support.
See Makefile for build instructions.

## Running the benchmark
See run_bench.sh for the multi-client benchmark script.

## ProVerif model
See pq_protocol.pv for the formal Dolev-Yao model (8/8 queries verified).

## License
MIT
