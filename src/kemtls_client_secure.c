/*
 * kemtls_client_secure.c - Secure KEMTLS Client with Mutual Authentication
 * 
 * Security: Pre-provisioned broker key, encrypted storage, device-bound
 * 
 * Compile:
 *   gcc -o kemtls_client_secure kemtls_client_secure.c kemtls.c \
 *       kemtls_metrics.c mqtt_protocol.c secure_keystore.c \
 *       -I. -loqs -lssl -lcrypto -lpthread
 */

#include "kemtls.h"
#include "kemtls_metrics.h"
#include "mqtt_protocol.h"
#include "secure_keystore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <termios.h>
#include <oqs/oqs.h>

#define KEMTLS_PORT 8884
#define BUFFER_SIZE 8192

static volatile int g_running = 1;
static kemtls_metrics_t g_metrics;
static keystore_ctx_t g_keystore;
static uint8_t g_client_pk[KYBER512_PK_BYTES];
static uint8_t g_client_sk[KYBER512_SK_BYTES];
static uint8_t g_trusted_broker_pk[KYBER512_PK_BYTES];
static bool g_broker_key_loaded = false;

void signal_handler(int sig) { (void)sig; printf("\n[client] Shutting down...\n"); g_running = 0; }

static int read_password(const char *prompt, char *password, size_t max_len) {
    struct termios old_term, new_term;
    printf("%s", prompt);
    fflush(stdout);
    
    if (isatty(STDIN_FILENO)) {
        tcgetattr(STDIN_FILENO, &old_term);
        new_term = old_term;
        new_term.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    }
    
    if (fgets(password, max_len, stdin) == NULL) {
        if (isatty(STDIN_FILENO)) tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        return -1;
    }
    
    if (isatty(STDIN_FILENO)) { tcsetattr(STDIN_FILENO, TCSANOW, &old_term); printf("\n"); }
    password[strcspn(password, "\n")] = 0;
    return 0;
}

static int init_client_keys(const char *keystore_path, const char *password, const char *device_id) {
    if (keystore_init(&g_keystore, device_id, keystore_path, password) != KEYSTORE_OK) return -1;
    
    size_t broker_pk_size = sizeof(g_trusted_broker_pk);
    int ret = keystore_load_key(&g_keystore, KEYTYPE_TRUSTED_BROKER, g_trusted_broker_pk, &broker_pk_size);
    
    if (ret == KEYSTORE_ERR_AUTH) {
        fprintf(stderr, "[client] FATAL: Trusted broker key tampered!\n");
        return -1;
    }
    if (ret != KEYSTORE_OK) {
        fprintf(stderr, "[client] ERROR: No trusted broker key. Run provisioning first:\n");
        fprintf(stderr, "  ./pqrguard_provision --init-client --import-broker broker_public_key.bin\n");
        return -1;
    }
    g_broker_key_loaded = true;
    printf("[client] Loaded trusted broker key\n");
    
    size_t pk_size = sizeof(g_client_pk), sk_size = sizeof(g_client_sk);
    int pk_ret = keystore_load_key(&g_keystore, KEYTYPE_CLIENT_PUBLIC, g_client_pk, &pk_size);
    int sk_ret = keystore_load_key(&g_keystore, KEYTYPE_CLIENT_SECRET, g_client_sk, &sk_size);
    
    if (pk_ret == KEYSTORE_OK && sk_ret == KEYSTORE_OK) {
        printf("[client] Loaded client keys\n");
        return 0;
    }
    if (pk_ret == KEYSTORE_ERR_AUTH || sk_ret == KEYSTORE_ERR_AUTH) {
        fprintf(stderr, "[client] FATAL: Client key tampering detected!\n");
        return -1;
    }
    
    printf("[client] Generating ML-KEM-512 keypair...\n");
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem || OQS_KEM_keypair(kem, g_client_pk, g_client_sk) != OQS_SUCCESS) {
        if (kem) OQS_KEM_free(kem);
        return -1;
    }
    OQS_KEM_free(kem);
    
    if (keystore_store_key(&g_keystore, KEYTYPE_CLIENT_PUBLIC, g_client_pk, sizeof(g_client_pk)) != KEYSTORE_OK ||
        keystore_store_key(&g_keystore, KEYTYPE_CLIENT_SECRET, g_client_sk, sizeof(g_client_sk)) != KEYSTORE_OK)
        return -1;
    
    char export_path[512];
    snprintf(export_path, sizeof(export_path), "%s/client_public_key.bin", keystore_path);
    FILE *f = fopen(export_path, "wb");
    if (f) { fwrite(g_client_pk, 1, sizeof(g_client_pk), f); fclose(f); }
    printf("[client] Exported: %s (send to broker admin)\n", export_path);
    return 0;
}

static int verify_broker_certificate(const uint8_t *received_pk) {
    if (!g_broker_key_loaded) return -1;
    
    volatile int diff = 0;
    for (size_t i = 0; i < KYBER512_PK_BYTES; i++)
        diff |= g_trusted_broker_pk[i] ^ received_pk[i];
    
    if (diff != 0) {
        fprintf(stderr, "[client] SECURITY ALERT: Broker key mismatch - connection rejected\n");
        return -1;
    }
    return 0;
}

static int send_handshake_msg(int sock, uint8_t msg_type, const uint8_t *data, size_t len) {
    uint8_t frame[4] = {msg_type, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF};
    if (send(sock, frame, 4, 0) != 4) return -1;
    if (len > 0 && send(sock, data, len, 0) != (ssize_t)len) return -1;
    g_metrics.handshake_bytes_sent += (4 + len);
    return 0;
}

static int recv_handshake_msg(int sock, uint8_t *msg_type, uint8_t *data, size_t *len) {
    uint8_t frame[4];
    if (recv(sock, frame, 4, MSG_WAITALL) != 4) return -1;
    *msg_type = frame[0];
    *len = (frame[1] << 16) | (frame[2] << 8) | frame[3];
    if (*len > BUFFER_SIZE) return -1;
    if (*len > 0 && recv(sock, data, *len, MSG_WAITALL) != (ssize_t)*len) return -1;
    g_metrics.handshake_bytes_recv += (4 + *len);
    return 0;
}

static int perform_kemtls_handshake(int sock, kemtls_ctx_t *ctx) {
    uint8_t buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    int ret;
    
    printf("[client] Starting secure KEMTLS handshake\n");
    METRICS_START_TIMER(total);
    
    // 1. ClientHello
    ret = kemtls_client_hello(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_CLIENT_HELLO, buffer, ret) != 0) return -1;
    
    // 2. ServerHello
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_SERVER_HELLO) return -1;
    if (kemtls_process_server_hello(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // 3. EncryptedExtensions
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_ENCRYPTED_EXTENSIONS) return -1;
    if (kemtls_process_encrypted_extensions(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // 4. Certificate
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_CERTIFICATE) return -1;
    if (kemtls_process_certificate(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // VERIFY BROKER
    printf("[client] Verifying broker certificate...\n");
    if (verify_broker_certificate(ctx->server_kem_pk) != 0) {
        fprintf(stderr, "[client] Handshake aborted: broker verification failed\n");
        return -1;
    }
    printf("[client] Broker verified - proceeding\n");
    
    // 5. KEM Encapsulation
    ret = kemtls_client_kem_encapsulation(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_KEM_ENCAPSULATION, buffer, ret) != 0) return -1;
    
    // 6. Server KEM CTS
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_SERVER_KEM_CTS) return -1;
    if (kemtls_process_server_kem_cts(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // 7. Client Finished
    ret = kemtls_client_finished(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_FINISHED, buffer, ret) != 0) return -1;
    
    // 8. Server Finished
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_FINISHED) return -1;
    if (kemtls_process_server_finished(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    METRICS_END_TIMER(total, &g_metrics, total_handshake_us);
    g_metrics.num_handshakes++;
    printf("[client] Handshake complete (%.2f ms) - MUTUAL AUTH SUCCESS\n\n", g_metrics.total_handshake_us / 1000.0);
    return 0;
}

static int mqtt_send_connect(int sock, kemtls_ctx_t *ctx, const char *client_id) {
    uint8_t mqtt_buffer[512], encrypted[1024];
    size_t mqtt_len;
    mqtt_connect_t connect = {.client_id = client_id, .keepalive = 60, .clean_session = true};
    if (mqtt_build_connect(&connect, mqtt_buffer, sizeof(mqtt_buffer), &mqtt_len) != MQTT_OK) return -1;
    
    int ret = kemtls_encrypt_data(ctx, mqtt_buffer, mqtt_len, encrypted, sizeof(encrypted));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_APPLICATION_DATA, encrypted, ret) != 0) return -1;
    
    uint8_t msg_type, recv_buffer[1024], plaintext[512];
    size_t msg_len;
    if (recv_handshake_msg(sock, &msg_type, recv_buffer, &msg_len) != 0 || msg_type != KEMTLS_APPLICATION_DATA) return -1;
    
    ret = kemtls_decrypt_data(ctx, recv_buffer, msg_len, plaintext, sizeof(plaintext));
    if (ret < 0) return -1;
    
    mqtt_connack_t connack;
    if (mqtt_parse_connack(plaintext, ret, &connack) != MQTT_OK || connack.return_code != 0) return -1;
    
    printf("[client] MQTT connected\n\n");
    return 0;
}

static int mqtt_send_publish(int sock, kemtls_ctx_t *ctx, const char *topic, const char *payload) {
    uint8_t mqtt_buffer[512], encrypted[1024];
    size_t mqtt_len;
    mqtt_publish_t publish = {.topic = topic, .payload = (const uint8_t *)payload, .payload_len = strlen(payload), .qos = MQTT_QOS_0};
    if (mqtt_build_publish(&publish, mqtt_buffer, sizeof(mqtt_buffer), &mqtt_len) != MQTT_OK) return -1;
    
    int ret = kemtls_encrypt_data(ctx, mqtt_buffer, mqtt_len, encrypted, sizeof(encrypted));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_APPLICATION_DATA, encrypted, ret) != 0) return -1;
    
    printf("[client] Published to '%s': %s\n", topic, payload);
    return 0;
}

static void generate_sensor_data(char *buffer, size_t size) {
    snprintf(buffer, size, "{\"hr\":%d,\"temp\":%.1f,\"ts\":%lu}",
             65 + (rand() % 25), 36.2 + (rand() % 15) / 10.0, (unsigned long)time(NULL));
}

int main(int argc, char *argv[]) {
    int sock = -1, ret = 1;
    kemtls_ctx_t *ctx = NULL;
    const char *broker_ip = NULL, *keystore_path = "./keystore", *device_id = "PQRGUARD_CLIENT";
    char password[256] = {0};
    
    printf("PQ-RGuard Secure Client\n");
    printf("Mutual Authentication + Encrypted Key Storage\n\n");
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) keystore_path = argv[++i];
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) device_id = argv[++i];
        else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s <broker_ip> [-k keystore] [-d device_id]\n", argv[0]);
            return 0;
        }
        else if (argv[i][0] != '-' && !broker_ip) broker_ip = argv[i];
    }
    
    if (!broker_ip) { printf("Usage: %s <broker_ip> [-k keystore] [-d device_id]\n", argv[0]); return 1; }
    if (read_password("Enter keystore password: ", password, sizeof(password)) != 0) return 1;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));
    
    printf("Device ID: %s\nKeystore: %s\n\n", device_id, keystore_path);
    
    if (init_client_keys(keystore_path, password, device_id) != 0) goto cleanup;
    keystore_secure_wipe(password, sizeof(password));
    
    kemtls_metrics_init(&g_metrics);
    if (kemtls_init() != KEMTLS_OK) goto cleanup;
    
    ctx = kemtls_ctx_new(true);
    if (!ctx) goto cleanup;
    memcpy(ctx->client_kem_pk, g_client_pk, KYBER512_PK_BYTES);
    memcpy(ctx->client_kem_sk, g_client_sk, KYBER512_SK_BYTES);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) goto cleanup;
    
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(KEMTLS_PORT)};
    inet_pton(AF_INET, broker_ip, &addr.sin_addr);
    
    printf("[client] Connecting to %s:%d...\n", broker_ip, KEMTLS_PORT);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto cleanup;
    printf("[client] TCP connected\n");
    
    if (perform_kemtls_handshake(sock, ctx) != 0) goto cleanup;
    if (mqtt_send_connect(sock, ctx, device_id) != 0) goto cleanup;
    
    printf("[client] Publishing sensor data every 5s (Ctrl+C to stop)\n\n");
    
    int msg_count = 0;
    while (g_running) {
        char sensor_json[256];
        generate_sensor_data(sensor_json, sizeof(sensor_json));
        if (mqtt_send_publish(sock, ctx, "iomt/vitals", sensor_json) == 0) msg_count++;
        for (int i = 0; i < 5 && g_running; i++) sleep(1);
    }
    
    printf("\n[client] Published %d messages\n", msg_count);
    kemtls_metrics_print(&g_metrics, "PQ-RGuard Secure Client");
    ret = 0;

cleanup:
    keystore_secure_wipe(g_client_pk, sizeof(g_client_pk));
    keystore_secure_wipe(g_client_sk, sizeof(g_client_sk));
    keystore_secure_wipe(g_trusted_broker_pk, sizeof(g_trusted_broker_pk));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&g_keystore);
    if (sock >= 0) close(sock);
    if (ctx) kemtls_ctx_free(ctx);
    kemtls_cleanup();
    printf("[client] Shutdown complete (keys wiped)\n");
    return ret;
}
