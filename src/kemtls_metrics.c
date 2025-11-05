/*
 * kemtls_metrics.c - Performance Measurement Implementation
 */

#include "kemtls_metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

// Initialization

void kemtls_metrics_init(kemtls_metrics_t *metrics) {
    memset(metrics, 0, sizeof(kemtls_metrics_t));
}

// Memory Profiling

size_t kemtls_metrics_get_current_memory(void) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return (size_t)usage.ru_maxrss * 1024; // Convert KB to bytes on Linux
}

size_t kemtls_metrics_get_peak_memory(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    
    char line[256];
    size_t peak_kb = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmPeak:", 7) == 0) {
            sscanf(line + 7, "%zu", &peak_kb);
            break;
        }
    }
    
    fclose(fp);
    return peak_kb * 1024; // Convert to bytes
}

// Reporting

void kemtls_metrics_print(const kemtls_metrics_t *metrics, const char *label) {
    printf("\n");
    printf("  KEMTLS Performance Metrics: %-30s \n", label);
    
    // Memory
    printf("\n📊 Memory Footprint:\n");
    printf("  RAM Usage:        %8zu bytes (%.2f KB)\n", 
           metrics->ram_usage_bytes, metrics->ram_usage_bytes / 1024.0);
    printf("  Peak Stack:       %8zu bytes (%.2f KB)\n",
           metrics->peak_stack_bytes, metrics->peak_stack_bytes / 1024.0);
    printf("  Flash Usage:      %8zu bytes (%.2f KB)\n",
           metrics->flash_usage_bytes, metrics->flash_usage_bytes / 1024.0);
    
    // Handshake Timing
    printf("\n⏱️  Handshake Timing Breakdown:\n");
    printf("  ClientHello:      %8lu μs\n", metrics->client_hello_time_us);
    printf("  ServerHello:      %8lu μs\n", metrics->server_hello_time_us);
    printf("  Certificate:      %8lu μs\n", metrics->certificate_time_us);
    printf("  KEM Encaps:       %8lu μs\n", metrics->kem_encaps_time_us);
    printf("  KEM Decaps:       %8lu μs\n", metrics->kem_decaps_time_us);
    printf("  KDF:              %8lu μs\n", metrics->kdf_time_us);
    printf("  Finished:         %8lu μs\n", metrics->finished_time_us);
    printf("  ─────────────────────────────\n");
    printf("  TOTAL Handshake:  %8lu μs (%.2f ms)\n",
           metrics->total_handshake_us, metrics->total_handshake_us / 1000.0);
    
    // Cryptographic Operations
    printf("\n🔐 Cryptographic Operations:\n");
    printf("  KeyGen:           %8lu μs  (%lu cycles)\n",
           metrics->keygen_time_us, metrics->cpu_cycles_keygen);
    printf("  Encapsulation:    %8lu μs  (%lu cycles)\n",
           metrics->encaps_time_us, metrics->cpu_cycles_encaps);
    printf("  Decapsulation:    %8lu μs  (%lu cycles)\n",
           metrics->decaps_time_us, metrics->cpu_cycles_decaps);
    printf("  Encryption (avg): %8lu μs  (%lu cycles)\n",
           metrics->encryption_time_us, metrics->cpu_cycles_encrypt);
    printf("  Decryption (avg): %8lu μs  (%lu cycles)\n",
           metrics->decryption_time_us, metrics->cpu_cycles_decrypt);
    
    // Network Overhead
    printf("\n📡 Network Overhead:\n");
    printf("  Handshake TX:     %8zu bytes\n", metrics->handshake_bytes_sent);
    printf("  Handshake RX:     %8zu bytes\n", metrics->handshake_bytes_recv);
    printf("  Total TX:         %8zu bytes\n", metrics->total_bytes_sent);
    printf("  Total RX:         %8zu bytes\n", metrics->total_bytes_recv);
    
    // Session Statistics
    printf("\n📈 Session Statistics:\n");
    printf("  Handshakes:       %8u\n", metrics->num_handshakes);
    printf("  Encrypted Msgs:   %8u\n", metrics->num_encrypted_msgs);
    printf("  Decrypted Msgs:   %8u\n", metrics->num_decrypted_msgs);
    
    // Energy Proxy
    printf("\n⚡ Energy Proxy (CPU Cycles):\n");
    printf("  Handshake:        %8lu cycles\n", metrics->cpu_cycles_handshake);
    printf("  Encrypt (total):  %8lu cycles\n", metrics->cpu_cycles_encrypt);
    printf("  Decrypt (total):  %8lu cycles\n", metrics->cpu_cycles_decrypt);
    
    printf("\n");
}

// CSV Export

void kemtls_metrics_to_csv(const kemtls_metrics_t *metrics, const char *filename) {
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        perror("fopen");
        return;
    }
    
    // Check if file is empty (write header)
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "scenario,ram_bytes,flash_bytes,handshake_us,keygen_us,encaps_us,"
                    "decaps_us,kdf_us,encrypt_us,decrypt_us,handshake_tx,handshake_rx,"
                    "total_tx,total_rx,cycles_handshake,cycles_encrypt,cycles_decrypt,"
                    "num_handshakes,num_encrypted,num_decrypted\n");
    }
    
    fprintf(fp, "KEMTLS,%zu,%zu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%zu,%zu,%zu,%zu,%lu,%lu,%lu,%u,%u,%u\n",
            metrics->ram_usage_bytes,
            metrics->flash_usage_bytes,
            metrics->total_handshake_us,
            metrics->keygen_time_us,
            metrics->encaps_time_us,
            metrics->decaps_time_us,
            metrics->kdf_time_us,
            metrics->encryption_time_us,
            metrics->decryption_time_us,
            metrics->handshake_bytes_sent,
            metrics->handshake_bytes_recv,
            metrics->total_bytes_sent,
            metrics->total_bytes_recv,
            metrics->cpu_cycles_handshake,
            metrics->cpu_cycles_encrypt,
            metrics->cpu_cycles_decrypt,
            metrics->num_handshakes,
            metrics->num_encrypted_msgs,
            metrics->num_decrypted_msgs);
    
    fclose(fp);
    printf("✓ Metrics exported to %s\n", filename);
}

// Comparison

void kemtls_metrics_compare(const kemtls_metrics_t *baseline,
                           const kemtls_metrics_t *pqc,
                           const char *scenario_name) {
    printf("\n");
    printf("  Performance Comparison: %-34s \n", scenario_name);
    
    printf("\n%-25s %15s %15s %10s\n", "Metric", "Baseline", "PQC", "Overhead");
    printf("─────────────────────────────────────────────────────────────────\n");
    
    // Handshake time
    double handshake_overhead = ((double)pqc->total_handshake_us / baseline->total_handshake_us - 1.0) * 100.0;
    printf("%-25s %12lu μs %12lu μs %9.1f%%\n", 
           "Handshake Time",
           baseline->total_handshake_us,
           pqc->total_handshake_us,
           handshake_overhead);
    
    // Memory
    double mem_overhead = ((double)pqc->ram_usage_bytes / baseline->ram_usage_bytes - 1.0) * 100.0;
    printf("%-25s %12zu B %12zu B %9.1f%%\n",
           "RAM Usage",
           baseline->ram_usage_bytes,
           pqc->ram_usage_bytes,
           mem_overhead);
    
    // Network
    double net_overhead = ((double)pqc->handshake_bytes_sent / baseline->handshake_bytes_sent - 1.0) * 100.0;
    printf("%-25s %12zu B %12zu B %9.1f%%\n",
           "Handshake TX",
           baseline->handshake_bytes_sent,
           pqc->handshake_bytes_sent,
           net_overhead);
    
    // Encryption
    double enc_overhead = ((double)pqc->encryption_time_us / baseline->encryption_time_us - 1.0) * 100.0;
    printf("%-25s %12lu μs %12lu μs %9.1f%%\n",
           "Encryption Time",
           baseline->encryption_time_us,
           pqc->encryption_time_us,
           enc_overhead);
    
    printf("\n");
}
