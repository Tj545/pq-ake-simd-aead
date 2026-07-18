CC = gcc
CFLAGS = -O3 -march=native -mavx2 -Wall -Wextra -std=c99 -D_POSIX_C_SOURCE=200809L -Du_int=unsigned

# ── liboqs paths ──────────────────────────────────────────────────
LIBOQS_DIR  = ../liboqs/build
LIBOQS_INC  = $(LIBOQS_DIR)/include
LIBOQS_LIB  = $(LIBOQS_DIR)/lib/liboqs.a

INCLUDES = -I$(LIBOQS_INC) -I.
LDFLAGS  = -lm -ldl -lssl -lcrypto -lrt -lpthread

SIMD_SRC = chachapoly_simd.c

.PHONY: all clean check test verify validate help

all: check server client test_simd
	@echo ""
	@echo "========================================================"
	@echo "  BUILD COMPLETE (UPDATED 2026 — Bug-fix revision)"
	@echo "========================================================"
	@echo "  Run 'make validate' BEFORE measuring performance."
	@echo "  Run 'make test' to see correctness + benchmark output."
	@echo "========================================================"

check:
	@if [ ! -f "$(LIBOQS_LIB)" ]; then \
		echo "ERROR: liboqs not found at $(LIBOQS_LIB)"; \
		echo "Build liboqs first."; \
		exit 1; \
	fi
	@echo "[+] liboqs: $(LIBOQS_LIB)"
	@echo "[+] SIMD:   chachapoly_simd.c (UPDATED) + chacha20_avx2.h (UPDATED)"

server: server.c $(SIMD_SRC) chacha20_avx2.h chachapoly_simd.h
	@echo "  Building server..."
	$(CC) $(CFLAGS) $(INCLUDES) server.c $(SIMD_SRC) $(LIBOQS_LIB) $(LDFLAGS) -o server

client: client.c $(SIMD_SRC) chacha20_avx2.h chachapoly_simd.h
	@echo "  Building client..."
	$(CC) $(CFLAGS) $(INCLUDES) client.c $(SIMD_SRC) $(LIBOQS_LIB) $(LDFLAGS) -o client

test_simd: test_simd.c $(SIMD_SRC) chacha20_avx2.h chachapoly_simd.h
	@echo "  Building SIMD benchmark..."
	$(CC) $(CFLAGS) test_simd.c $(SIMD_SRC) -lm -o test_simd

# Run correctness validation BEFORE benchmark.
# This is now part of test_simd itself (it bails on test failure).
validate: test_simd
	@echo "Running validation suite + benchmark..."
	./test_simd

test: validate

# Stronger check: build with UB sanitizer to catch any remaining
# strict-aliasing or alignment issues.
asan:
	$(CC) -O1 -g -fsanitize=address,undefined,alignment \
		-march=native -mavx2 -Wall -Wextra -std=c99 \
		-D_POSIX_C_SOURCE=199309L \
		test_simd.c $(SIMD_SRC) -lm -o test_simd_asan
	@echo "[+] Built test_simd_asan with UBSan + ASan"
	@echo "    Run: ./test_simd_asan"

clean:
	rm -f server client test_simd test_simd_asan *.o

help:
	@echo "Targets:"
	@echo "  make           - Build everything"
	@echo "  make validate  - Run correctness tests + benchmark"
	@echo "  make asan      - Build with UB/address sanitizer for paranoia"
	@echo "  make clean     - Remove binaries"
