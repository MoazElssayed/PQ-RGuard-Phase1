/*
 * kemtls_metrics.h - Performance Measurement Framework
 * 
 * Comprehensive metrics for PQ-RGuard+ evaluation
 */

#ifndef KEMTLS_METRICS_H
#define KEMTLS_METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// ============================================================================
// Performance Metrics Structure
// ============================================================================

typedef struct {
    // Memory footprint
    size_t ram_usage_bytes;
    size_t flash_usage_bytes;
    size_t peak_stack_bytes;
    
    // Timing breakdown (microseconds)
    uint64_t keygen_time_us;
    uint64_t encaps_time_us;
    uint64_t decaps_time_us;
    uint64_t kdf_time_us;
    uint64_t total_handshake_us;
    uint64_t encryption_time_us;
    uint64_t decryption_time_us;
    
    // Energy proxy (CPU cycles)
    uint64_t cpu_cycles_keygen;
    uint64_t cpu_cycles_encaps;
    uint64_t cpu_cycles_decaps;
    uint64_t cpu_cycles_kdf;
    uint64_t cpu_cycles_handshake;
    uint64_t cpu_cycles_encrypt;
    uint64_t cpu_cycles_decrypt;
    
    // Network overhead
    size_t handshake_bytes_sent;
    size_t handshake_bytes_recv;
    size_t total_bytes_sent;
    size_t total_bytes_recv;
    
    // Handshake breakdown
    uint64_t client_hello_time_us;
    uint64_t server_hello_time_us;
    uint64_t certificate_time_us;
    uint64_t kem_encaps_time_us;
    uint64_t kem_decaps_time_us;
    uint64_t finished_time_us;
    
    // Session info
    uint32_t num_handshakes;
    uint32_t num_encrypted_msgs;
    uint32_t num_decrypted_msgs;
    
} kemtls_metrics_t;

// ============================================================================
// Timing Utilities
// ============================================================================

// High-resolution timer (nanosecond precision)
static inline uint64_t metrics_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static inline uint64_t metrics_time_us(void) {
    return metrics_time_ns() / 1000;
}

// CPU cycle counter (architecture-specific)
#if defined(__aarch64__) || defined(__arm__)
// ARM64 cycle counter
static inline uint64_t metrics_rdtsc(void) {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r" (val));
    return val;
}
#elif defined(__x86_64__) || defined(__i386__)
// x86 RDTSC
static inline uint64_t metrics_rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#else
// Fallback to time-based approximation
static inline uint64_t metrics_rdtsc(void) {
    return metrics_time_ns();
}
#endif

// ============================================================================
// API Functions
// ============================================================================

// Initialize metrics structure
void kemtls_metrics_init(kemtls_metrics_t *metrics);

// Print comprehensive report
void kemtls_metrics_print(const kemtls_metrics_t *metrics, const char *label);

// Export to CSV for analysis
void kemtls_metrics_to_csv(const kemtls_metrics_t *metrics, const char *filename);

// Compare two scenarios
void kemtls_metrics_compare(const kemtls_metrics_t *baseline,
                           const kemtls_metrics_t *pqc,
                           const char *scenario_name);

// Memory profiling
size_t kemtls_metrics_get_current_memory(void);
size_t kemtls_metrics_get_peak_memory(void);

// ============================================================================
// Timing Macros
// ============================================================================

#define METRICS_START_TIMER(var) \
    uint64_t var##_start = metrics_time_us()

#define METRICS_END_TIMER(var, metrics_ptr, field) \
    do { \
        uint64_t var##_end = metrics_time_us(); \
        (metrics_ptr)->field = var##_end - var##_start; \
    } while(0)

#define METRICS_START_CYCLES(var) \
    uint64_t var##_cycles_start = metrics_rdtsc()

#define METRICS_END_CYCLES(var, metrics_ptr, field) \
    do { \
        uint64_t var##_cycles_end = metrics_rdtsc(); \
        (metrics_ptr)->field = var##_cycles_end - var##_cycles_start; \
    } while(0)

#endif // KEMTLS_METRICS_H
