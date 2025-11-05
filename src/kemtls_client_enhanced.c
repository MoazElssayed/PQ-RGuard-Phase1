/*
 * kemtls_client_enhanced.c - Enhanced KEMTLS Client
 * 
 * Features:
 * - Performance metrics collection
 * - Proper MQTT CONNECT + PUBLISH
 * - Memory profiling
 * 
 * Compile:
 *   gcc -o kemtls_client_enhanced kemtls_client_enhanced.c kemtls.c \
 *       kemtls_metrics.c mqtt_protocol.c -I. -loqs -lssl -lcrypto -lpthread
 */

#include "kemtls.h"
#include "kemtls_metrics.h"
#include "mqtt_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#define KEMTLS_PORT 8884
#define BUFFER_SIZE 8192

static volatile int g_running = 1;
static kemtls_metrics_t g_metrics;

void signal_handler(int sig) {
    printf("\nShutting down...\n");
    g_running = 0;
}

// Send/recv functions (same as before)
int send_handshake_msg(int sock, uint8_t msg_type, const uint8_t *data, size_t len) {
    uint8_t frame[4];
    frame[0] = msg_type;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    
    if (send(sock, frame, 4, 0) != 4) return -1;
    if (len > 0 && send(sock, data, len, 0) != (ssize_t)len) return -1;
    
    g_metrics.handshake_bytes_sent += (4 + len);
    g_metrics.total_bytes_sent += (4 + len);
    
    return 0;
}

int recv_handshake_msg(int sock, uint8_t *msg_type, uint8_t *data, size_t *len) {
    uint8_t frame[4];
    
    if (recv(sock, frame, 4, MSG_WAITALL) != 4) return -1;
    
    *msg_type = frame[0];
    *len = (frame[1] << 16) | (frame[2] << 8) | frame[3];
    
    if (*len > BUFFER_SIZE) return -1;
    if (*len > 0 && recv(sock, data, *len, MSG_WAITALL) != (ssize_t)*len) return -1;
    
    g_metrics.handshake_bytes_recv += (4 + *len);
    g_metrics.total_bytes_recv += (4 + *len);
    
    return 0;
}

// Instrumented handshake
int perform_kemtls_handshake(int sock, kemtls_ctx_t *ctx) {
    uint8_t buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    int ret;
    
    printf("\n=== KEMTLS Handshake Start ===\n");
    
    METRICS_START_TIMER(total);
    METRICS_START_CYCLES(total);
    
    // 1. ClientHello
    METRICS_START_TIMER(ch);
    ret = kemtls_client_hello(ctx, buffer, sizeof(buffer));
    METRICS_END_TIMER(ch, &g_metrics, client_hello_time_us);
    
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_CLIENT_HELLO, buffer, ret) != 0) return -1;
    
    // 2. ServerHello
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_SERVER_HELLO) return -1;
    
    METRICS_START_TIMER(sh);
    ret = kemtls_process_server_hello(ctx, buffer, msg_len);
    METRICS_END_TIMER(sh, &g_metrics, server_hello_time_us);
    if (ret != KEMTLS_OK) return -1;
    
    // 3. EncryptedExtensions
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_ENCRYPTED_EXTENSIONS) return -1;
    ret = kemtls_process_encrypted_extensions(ctx, buffer, msg_len);
    if (ret != KEMTLS_OK) return -1;
    
    // 4. Certificate
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_CERTIFICATE) return -1;
    
    METRICS_START_TIMER(cert);
    ret = kemtls_process_certificate(ctx, buffer, msg_len);
    METRICS_END_TIMER(cert, &g_metrics, certificate_time_us);
    if (ret != KEMTLS_OK) return -1;
    
    // 5. KEM Encapsulation
    METRICS_START_TIMER(encaps);
    METRICS_START_CYCLES(encaps);
    ret = kemtls_client_kem_encapsulation(ctx, buffer, sizeof(buffer));
    METRICS_END_CYCLES(encaps, &g_metrics, cpu_cycles_encaps);
    METRICS_END_TIMER(encaps, &g_metrics, kem_encaps_time_us);
    
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_KEM_ENCAPSULATION, buffer, ret) != 0) return -1;
    
    // 6. Server KEM CTS
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_SERVER_KEM_CTS) return -1;
    
    METRICS_START_TIMER(decaps);
    METRICS_START_CYCLES(decaps);
    ret = kemtls_process_server_kem_cts(ctx, buffer, msg_len);
    METRICS_END_CYCLES(decaps, &g_metrics, cpu_cycles_decaps);
    METRICS_END_TIMER(decaps, &g_metrics, kem_decaps_time_us);
    
    if (ret != KEMTLS_OK) return -1;
    
    // 7. Client Finished
    METRICS_START_TIMER(fin);
    ret = kemtls_client_finished(ctx, buffer, sizeof(buffer));
    METRICS_END_TIMER(fin, &g_metrics, finished_time_us);
    
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_FINISHED, buffer, ret) != 0) return -1;
    
    // 8. Server Finished
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_FINISHED) return -1;
    ret = kemtls_process_server_finished(ctx, buffer, msg_len);
    if (ret != KEMTLS_OK) return -1;
    
    METRICS_END_CYCLES(total, &g_metrics, cpu_cycles_handshake);
    METRICS_END_TIMER(total, &g_metrics, total_handshake_us);
    
    g_metrics.num_handshakes++;
    
    printf("=== KEMTLS Handshake Complete ===\n\n");
    
    return 0;
}

// Send MQTT CONNECT
int mqtt_send_connect(int sock, kemtls_ctx_t *ctx, const char *client_id) {
    uint8_t mqtt_buffer[512];
    uint8_t encrypted[1024];
    size_t mqtt_len;
    
    mqtt_connect_t connect = {
        .client_id = client_id,
        .username = NULL,
        .password = NULL,
        .will_topic = NULL,
        .will_payload = NULL,
        .will_payload_len = 0,
        .will_qos = 0,
        .will_retain = false,
        .keepalive = 60,
        .clean_session = true
    };
    
    int ret = mqtt_build_connect(&connect, mqtt_buffer, sizeof(mqtt_buffer), &mqtt_len);
    if (ret != MQTT_OK) {
        fprintf(stderr, "MQTT CONNECT build failed: %s\n", mqtt_strerror(ret));
        return -1;
    }
    
    printf("📤 Sending MQTT CONNECT (%zu bytes)\n", mqtt_len);
    
    // Encrypt
    ret = kemtls_encrypt_data(ctx, mqtt_buffer, mqtt_len, encrypted, sizeof(encrypted));
    if (ret < 0) return -1;
    
    size_t encrypted_len = ret;
    g_metrics.num_encrypted_msgs++;
    
    // Send
    if (send_handshake_msg(sock, KEMTLS_APPLICATION_DATA, encrypted, encrypted_len) != 0) {
        return -1;
    }
    
    printf("   Encrypted: %zu bytes\n", encrypted_len);
    
    // Wait for CONNACK
    uint8_t msg_type;
    size_t msg_len;
    uint8_t recv_buffer[1024];
    
    if (recv_handshake_msg(sock, &msg_type, recv_buffer, &msg_len) != 0) {
        return -1;
    }
    
    if (msg_type != KEMTLS_APPLICATION_DATA) {
        fprintf(stderr, "Expected APPLICATION_DATA, got 0x%02x\n", msg_type);
        return -1;
    }
    
    uint8_t plaintext[512];
    ret = kemtls_decrypt_data(ctx, recv_buffer, msg_len, plaintext, sizeof(plaintext));
    if (ret < 0) return -1;
    
    size_t plain_len = ret;
    g_metrics.num_decrypted_msgs++;
    
    mqtt_connack_t connack;
    if (mqtt_parse_connack(plaintext, plain_len, &connack) != MQTT_OK) {
        fprintf(stderr, "CONNACK parse failed\n");
        return -1;
    }
    
    if (connack.return_code != 0) {
        fprintf(stderr, "MQTT connection refused: code %d\n", connack.return_code);
        return -1;
    }
    
    printf("✓ MQTT CONNECTED (return code: %d)\n\n", connack.return_code);
    
    return 0;
}

// Send MQTT PUBLISH
int mqtt_send_publish(int sock, kemtls_ctx_t *ctx, const char *topic, const char *payload) {
    uint8_t mqtt_buffer[512];
    uint8_t encrypted[1024];
    size_t mqtt_len;
    
    mqtt_publish_t publish = {
        .topic = topic,
        .payload = (const uint8_t *)payload,
        .payload_len = strlen(payload),
        .qos = MQTT_QOS_0,
        .retain = false,
        .dup = false,
        .packet_id = 0
    };
    
    int ret = mqtt_build_publish(&publish, mqtt_buffer, sizeof(mqtt_buffer), &mqtt_len);
    if (ret != MQTT_OK) return -1;
    
    // Encrypt
    METRICS_START_TIMER(enc);
    METRICS_START_CYCLES(enc);
    ret = kemtls_encrypt_data(ctx, mqtt_buffer, mqtt_len, encrypted, sizeof(encrypted));
    METRICS_END_CYCLES(enc, &g_metrics, cpu_cycles_encrypt);
    METRICS_END_TIMER(enc, &g_metrics, encryption_time_us);
    
    if (ret < 0) return -1;
    
    size_t encrypted_len = ret;
    g_metrics.num_encrypted_msgs++;
    
    // Send
    if (send_handshake_msg(sock, KEMTLS_APPLICATION_DATA, encrypted, encrypted_len) != 0) {
        return -1;
    }
    
    printf("📤 Published to '%s': %s\n", topic, payload);
    printf("   Plaintext: %zu bytes → Encrypted: %zu bytes\n", mqtt_len, encrypted_len);
    
    return 0;
}

// Generate sensor data
void generate_sensor_data(char *buffer, size_t size) {
    int hr = 65 + (rand() % 25);
    float temp = 36.2 + (rand() % 15) / 10.0;
    int glucose = 85 + (rand() % 35);
    int spo2 = 95 + (rand() % 6);
    
    snprintf(buffer, size,
             "{\"device\":\"pi_client\",\"hr\":%d,\"temp\":%.1f,"
             "\"glucose\":%d,\"spo2\":%d,\"ts\":%lu}",
             hr, temp, glucose, spo2, (unsigned long)time(NULL));
}

int main(int argc, char *argv[]) {
    int sock = -1;
    kemtls_ctx_t *ctx = NULL;
    int ret = 1;
    
    printf("   KEMTLS Enhanced Client - Raspberry Pi 5                   \n");
    printf("   With Performance Metrics & Real MQTT                      \n");
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <broker_ip>\n", argv[0]);
        return 1;
    }
    
    const char *broker_ip = argv[1];
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));
    
    // Initialize metrics
    kemtls_metrics_init(&g_metrics);
    g_metrics.ram_usage_bytes = kemtls_metrics_get_current_memory();
    
    // Initialize KEMTLS
    if (kemtls_init() != KEMTLS_OK) {
        fprintf(stderr, "KEMTLS init failed\n");
        return 1;
    }
    
    // Create context
    METRICS_START_TIMER(keygen);
    METRICS_START_CYCLES(keygen);
    ctx = kemtls_ctx_new(true);
    METRICS_END_CYCLES(keygen, &g_metrics, cpu_cycles_keygen);
    METRICS_END_TIMER(keygen, &g_metrics, keygen_time_us);
    
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        goto cleanup;
    }
    
    // Connect to broker
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(KEMTLS_PORT);
    inet_pton(AF_INET, broker_ip, &addr.sin_addr);
    
    printf("Connecting to %s:%d...\n", broker_ip, KEMTLS_PORT);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        goto cleanup;
    }
    printf("✓ TCP connected\n");
    
    // Perform handshake
    if (perform_kemtls_handshake(sock, ctx) != 0) {
        fprintf(stderr, "Handshake failed\n");
        goto cleanup;
    }
    
    // Send MQTT CONNECT
    if (mqtt_send_connect(sock, ctx, "kemtls_pi_client") != 0) {
        fprintf(stderr, "MQTT CONNECT failed\n");
        goto cleanup;
    }
    
    // Main loop - publish sensor data
    printf("Publishing sensor data every 5 seconds...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    int msg_count = 0;
    while (g_running) {
        char sensor_json[256];
        generate_sensor_data(sensor_json, sizeof(sensor_json));
        
        if (mqtt_send_publish(sock, ctx, "iomt/vitals", sensor_json) == 0) {
            msg_count++;
        }
        
        for (int i = 0; i < 5 && g_running; i++) {
            sleep(1);
        }
    }
    
    printf("\n\nPublished %d messages\n", msg_count);
    
    // Final metrics
    g_metrics.peak_stack_bytes = kemtls_metrics_get_peak_memory();
    
    kemtls_print_stats(ctx);
    kemtls_metrics_print(&g_metrics, "KEMTLS Client");
    kemtls_metrics_to_csv(&g_metrics, "kemtls_performance.csv");
    
    ret = 0;

cleanup:
    if (sock >= 0) close(sock);
    if (ctx) kemtls_ctx_free(ctx);
    kemtls_cleanup();
    
    printf("\n✓ Client shutdown complete\n");
    return ret;
}
