#!/bin/bash


echo           " PQ-RGuard+ Performance Benchmarks"
echo ""

RESULTS_DIR="../results"
mkdir -p "$RESULTS_DIR"

# Create benchmark script
cat > bench_crypto.c << 'BENCH_EOF'
#include <stdio.h>
#include <oqs/oqs.h>
#include <time.h>

uint64_t get_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t pk[800], sk[1632], ct[768], ss1[32], ss2[32];
    
    printf("Kyber-512 Benchmark (1000 iterations)\n");
    printf("=====================================\n\n");
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        OQS_KEM_keypair(kem, pk, sk);
    }
    
    // KeyGen
    uint64_t start = get_ns();
    for (int i = 0; i < 1000; i++) {
        OQS_KEM_keypair(kem, pk, sk);
    }
    double keygen = (get_ns() - start) / 1000000000.0 / 1000.0 * 1000.0;
    
    // Encaps
    OQS_KEM_keypair(kem, pk, sk);
    start = get_ns();
    for (int i = 0; i < 1000; i++) {
        OQS_KEM_encaps(kem, ct, ss1, pk);
    }
    double encaps = (get_ns() - start) / 1000000000.0 / 1000.0 * 1000.0;
    
    // Decaps
    start = get_ns();
    for (int i = 0; i < 1000; i++) {
        OQS_KEM_decaps(kem, ss2, ct, sk);
    }
    double decaps = (get_ns() - start) / 1000000000.0 / 1000.0 * 1000.0;
    
    printf("KeyGen:  %.3f ms\n", keygen);
    printf("Encaps:  %.3f ms\n", encaps);
    printf("Decaps:  %.3f ms\n", decaps);
    printf("Total:   %.3f ms\n", keygen + encaps + decaps);
    
    // Save to CSV
    FILE *f = fopen("../results/crypto_bench.csv", "w");
    fprintf(f, "Operation,Time_ms\n");
    fprintf(f, "KeyGen,%.3f\n", keygen);
    fprintf(f, "Encaps,%.3f\n", encaps);
    fprintf(f, "Decaps,%.3f\n", decaps);
    fclose(f);
    
    OQS_KEM_free(kem);
    return 0;
}
BENCH_EOF

gcc -O3 -march=native bench_crypto.c -o bench_crypto -loqs
./bench_crypto

echo ""
echo "✓ Results saved to: $RESULTS_DIR/crypto_bench.csv"
