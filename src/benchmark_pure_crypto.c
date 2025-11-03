#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

uint64_t rdtsc() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    
    uint8_t pk[800], sk[1632], ct[768], ss1[32], ss2[32];
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        OQS_KEM_keypair(kem, pk, sk);
    }
    
    printf("Benchmarking Kyber-512 (1000 iterations)...\n\n");
    
    // Benchmark KeyGen
    uint64_t total = 0;
    for (int i = 0; i < 1000; i++) {
        uint64_t start = rdtsc();
        OQS_KEM_keypair(kem, pk, sk);
        uint64_t end = rdtsc();
        total += (end - start);
    }
    printf("KeyGen:   %.3f ms (avg)\n", total / 1000.0 / 1000000.0);
    
    // Benchmark Encaps
    total = 0;
    OQS_KEM_keypair(kem, pk, sk);
    for (int i = 0; i < 1000; i++) {
        uint64_t start = rdtsc();
        OQS_KEM_encaps(kem, ct, ss1, pk);
        uint64_t end = rdtsc();
        total += (end - start);
    }
    printf("Encaps:   %.3f ms (avg)\n", total / 1000.0 / 1000000.0);
    
    // Benchmark Decaps
    total = 0;
    OQS_KEM_encaps(kem, ct, ss1, pk);
    for (int i = 0; i < 1000; i++) {
        uint64_t start = rdtsc();
        OQS_KEM_decaps(kem, ss2, ct, sk);
        uint64_t end = rdtsc();
        total += (end - start);
    }
    printf("Decaps:   %.3f ms (avg)\n", total / 1000.0 / 1000000.0);
    
    // Total for one handshake (1 keygen + 2 encaps + 2 decaps)
    printf("\n=== Theoretical Minimum Handshake (crypto only) ===\n");
    printf("This is what papers measure!\n");
    
    OQS_KEM_free(kem);
    return 0;
}
