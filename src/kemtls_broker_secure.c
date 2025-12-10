/*
 * kemtls_broker_secure.c - Secure KEMTLS Broker with Mutual Authentication
 * 
 * Security: Encrypted keys at rest, client verification, device-bound storage
 * 
 * Compile:
 *   gcc -o kemtls_broker_secure kemtls_broker_secure.c kemtls.c \
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
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <termios.h>
#include <oqs/oqs.h>

#define KEMTLS_PORT 8884
#define MOSQUITTO_HOST "127.0.0.1"
#define MOSQUITTO_PORT 1883
#define MAX_CLIENTS 10
#define BUFFER_SIZE 8192

static volatile int g_running = 1;
static keystore_ctx_t g_keystore;
static uint8_t g_broker_kem_pk[KYBER512_PK_BYTES];
static uint8_t g_broker_kem_sk[KYBER512_SK_BYTES];

typedef struct {
    int client_fd;
    int mosquitto_fd;
    kemtls_ctx_t *ctx;
    kemtls_metrics_t metrics;
    struct sockaddr_in client_addr;
    pthread_t thread;
    int slot;
    volatile int active;
    uint8_t client_pk[KYBER512_PK_BYTES];
    bool client_authenticated;
} client_context_t;

static client_context_t g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    (void)sig;
    printf("\n[broker] Shutting down...\n");
    g_running = 0;
}

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
    
    if (isatty(STDIN_FILENO)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        printf("\n");
    }
    password[strcspn(password, "\n")] = 0;
    return 0;
}

static int init_broker_keys(const char *keystore_path, const char *password) {
    if (keystore_init(&g_keystore, "PQRGUARD_BROKER", keystore_path, password) != KEYSTORE_OK) {
        fprintf(stderr, "[broker] Failed to initialize keystore\n");
        return -1;
    }
    
    size_t pk_size = sizeof(g_broker_kem_pk);
    size_t sk_size = sizeof(g_broker_kem_sk);
    
    int pk_ret = keystore_load_key(&g_keystore, KEYTYPE_BROKER_PUBLIC, g_broker_kem_pk, &pk_size);
    int sk_ret = keystore_load_key(&g_keystore, KEYTYPE_BROKER_SECRET, g_broker_kem_sk, &sk_size);
    
    if (pk_ret == KEYSTORE_OK && sk_ret == KEYSTORE_OK) {
        printf("[broker] Loaded keys from secure storage\n");
        return 0;
    }
    
    if (pk_ret == KEYSTORE_ERR_AUTH || sk_ret == KEYSTORE_ERR_AUTH) {
        fprintf(stderr, "[broker] FATAL: Key tampering detected!\n");
        return -1;
    }
    
    printf("[broker] Generating new ML-KEM-512 keypair...\n");
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem || OQS_KEM_keypair(kem, g_broker_kem_pk, g_broker_kem_sk) != OQS_SUCCESS) {
        if (kem) OQS_KEM_free(kem);
        return -1;
    }
    OQS_KEM_free(kem);
    
    if (keystore_store_key(&g_keystore, KEYTYPE_BROKER_PUBLIC, g_broker_kem_pk, sizeof(g_broker_kem_pk)) != KEYSTORE_OK ||
        keystore_store_key(&g_keystore, KEYTYPE_BROKER_SECRET, g_broker_kem_sk, sizeof(g_broker_kem_sk)) != KEYSTORE_OK) {
        return -1;
    }
    
    char export_path[512];
    snprintf(export_path, sizeof(export_path), "%s/broker_public_key.bin", keystore_path);
    FILE *f = fopen(export_path, "wb");
    if (f) {
        fwrite(g_broker_kem_pk, 1, sizeof(g_broker_kem_pk), f);
        fclose(f);
        printf("[broker] Exported: %s\n", export_path);
        printf("[broker] WARNING: Distribute to clients via secure channel only!\n");
    }
    return 0;
}

static int load_trusted_clients(void) {
    uint8_t client_keys[MAX_CLIENTS * KYBER512_PK_BYTES];
    size_t num_clients;
    
    int ret = keystore_load_trusted_clients(&g_keystore, client_keys, KYBER512_PK_BYTES, MAX_CLIENTS, &num_clients);
    if (ret == KEYSTORE_ERR_FILE) {
        printf("[broker] No trusted clients configured. Run provisioning tool first.\n");
        return 0;
    }
    return (ret == KEYSTORE_OK) ? 0 : -1;
}

static bool verify_client(const uint8_t *client_pk) {
    if (!keystore_is_client_trusted(&g_keystore, client_pk, KYBER512_PK_BYTES)) {
        fprintf(stderr, "[broker] SECURITY: Unauthorized client rejected\n");
        return false;
    }
    return true;
}

static int send_handshake_msg(int sock, uint8_t msg_type, const uint8_t *data, size_t len) {
    uint8_t frame[4] = {msg_type, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF};
    if (send(sock, frame, 4, 0) != 4) return -1;
    if (len > 0 && send(sock, data, len, 0) != (ssize_t)len) return -1;
    return 0;
}

static int recv_handshake_msg(int sock, uint8_t *msg_type, uint8_t *data, size_t *len) {
    uint8_t frame[4];
    if (recv(sock, frame, 4, MSG_WAITALL) != 4) return -1;
    *msg_type = frame[0];
    *len = (frame[1] << 16) | (frame[2] << 8) | frame[3];
    if (*len > BUFFER_SIZE) return -1;
    if (*len > 0 && recv(sock, data, *len, MSG_WAITALL) != (ssize_t)*len) return -1;
    return 0;
}

static int connect_to_mosquitto(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(MOSQUITTO_PORT)};
    inet_pton(AF_INET, MOSQUITTO_HOST, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

static int perform_server_handshake(client_context_t *client) {
    uint8_t buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    int ret;
    kemtls_ctx_t *ctx = client->ctx;
    int sock = client->client_fd;
    
    printf("[client %d] Starting secure KEMTLS handshake\n", client->slot);
    METRICS_START_TIMER(total);
    uint64_t ltls_start = kemtls_time_ms();
    
    // 1. ClientHello
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_CLIENT_HELLO) return -1;
    if (kemtls_process_client_hello(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // Verify client
    memcpy(client->client_pk, ctx->client_kem_pk, KYBER512_PK_BYTES);
    if (!verify_client(client->client_pk)) {
        printf("[client %d] REJECTED - not in trusted list\n", client->slot);
        return -1;
    }
    client->client_authenticated = true;
    printf("[client %d] Client verified\n", client->slot);
    
    // 2. ServerHello
    ret = kemtls_server_hello(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_SERVER_HELLO, buffer, ret) != 0) return -1;
    
    printf("[client %d] LTLS: %lu ms\n", client->slot, kemtls_time_ms() - ltls_start);
    
    // 3. EncryptedExtensions
    ret = kemtls_server_encrypted_extensions(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_ENCRYPTED_EXTENSIONS, buffer, ret) != 0) return -1;
    
    // 4. Certificate
    kemtls_certificate_t cert;
    strncpy((char *)cert.subject, "pqrguard.broker", sizeof(cert.subject));
    memcpy(cert.pk_kem, g_broker_kem_pk, KYBER512_PK_BYTES);
    ret = kemtls_server_certificate(ctx, &cert, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_CERTIFICATE, buffer, ret) != 0) return -1;
    
    // 5. Client KEM Encapsulation
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_KEM_ENCAPSULATION) return -1;
    if (kemtls_process_client_kem_encaps(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // 6. Server KEM CTS
    ret = kemtls_server_kem_cts(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_SERVER_KEM_CTS, buffer, ret) != 0) return -1;
    
    // 7. Client Finished
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0 || msg_type != KEMTLS_FINISHED) return -1;
    if (kemtls_process_client_finished(ctx, buffer, msg_len) != KEMTLS_OK) return -1;
    
    // 8. Server Finished
    ret = kemtls_server_finished(ctx, buffer, sizeof(buffer));
    if (ret < 0 || send_handshake_msg(sock, KEMTLS_FINISHED, buffer, ret) != 0) return -1;
    
    METRICS_END_TIMER(total, &client->metrics, total_handshake_us);
    client->metrics.num_handshakes++;
    
    printf("[client %d] Handshake complete (%.2f ms) - MUTUAL AUTH SUCCESS\n",
           client->slot, client->metrics.total_handshake_us / 1000.0);
    return 0;
}

static void *client_handler(void *arg) {
    client_context_t *client = (client_context_t *)arg;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->client_addr.sin_addr, client_ip, sizeof(client_ip));
    
    printf("[client %d] Connection from %s:%d\n", client->slot, client_ip, ntohs(client->client_addr.sin_port));
    
    kemtls_metrics_init(&client->metrics);
    client->client_authenticated = false;
    
    if (perform_server_handshake(client) != 0 || !client->client_authenticated) goto cleanup;
    
    client->mosquitto_fd = connect_to_mosquitto();
    if (client->mosquitto_fd < 0) goto cleanup;
    
    printf("[client %d] Proxying MQTT (authenticated)\n", client->slot);
    
    uint8_t recv_buffer[BUFFER_SIZE], plain_buffer[BUFFER_SIZE], encrypted_buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    
    while (client->active && g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client->client_fd, &read_fds);
        FD_SET(client->mosquitto_fd, &read_fds);
        int max_fd = (client->client_fd > client->mosquitto_fd) ? client->client_fd : client->mosquitto_fd;
        struct timeval timeout = {.tv_sec = 1};
        
        if (select(max_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0) continue;
        
        if (FD_ISSET(client->client_fd, &read_fds)) {
            if (recv_handshake_msg(client->client_fd, &msg_type, recv_buffer, &msg_len) != 0) break;
            if (msg_type == KEMTLS_APPLICATION_DATA) {
                int ret = kemtls_decrypt_data(client->ctx, recv_buffer, msg_len, plain_buffer, sizeof(plain_buffer));
                if (ret >= 0) send(client->mosquitto_fd, plain_buffer, ret, 0);
            }
        }
        
        if (FD_ISSET(client->mosquitto_fd, &read_fds)) {
            ssize_t n = recv(client->mosquitto_fd, plain_buffer, sizeof(plain_buffer), 0);
            if (n <= 0) break;
            int ret = kemtls_encrypt_data(client->ctx, plain_buffer, n, encrypted_buffer, sizeof(encrypted_buffer));
            if (ret >= 0) send_handshake_msg(client->client_fd, KEMTLS_APPLICATION_DATA, encrypted_buffer, ret);
        }
    }

cleanup:
    keystore_secure_wipe(client->client_pk, sizeof(client->client_pk));
    if (client->client_fd >= 0) close(client->client_fd);
    if (client->mosquitto_fd >= 0) close(client->mosquitto_fd);
    if (client->ctx) kemtls_ctx_free(client->ctx);
    client->client_fd = client->mosquitto_fd = -1;
    client->ctx = NULL;
    
    pthread_mutex_lock(&g_clients_mutex);
    client->active = 0;
    pthread_mutex_unlock(&g_clients_mutex);
    
    printf("[client %d] Session ended\n", client->slot);
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_fd = -1, ret = 1;
    const char *keystore_path = "./keystore";
    char password[256] = {0};
    
    printf("PQ-RGuard Secure Broker\n");
    printf("Mutual Authentication + Encrypted Key Storage\n\n");
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) keystore_path = argv[++i];
        else if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [-k keystore_path]\n", argv[0]);
            return 0;
        }
    }
    
    if (read_password("Enter keystore password: ", password, sizeof(password)) != 0) return 1;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    if (kemtls_init() != KEMTLS_OK) goto cleanup;
    if (init_broker_keys(keystore_path, password) != 0) goto cleanup;
    keystore_secure_wipe(password, sizeof(password));
    if (load_trusted_clients() != 0) goto cleanup;
    
    memset(g_clients, 0, sizeof(g_clients));
    for (int i = 0; i < MAX_CLIENTS; i++) { g_clients[i].slot = i; g_clients[i].client_fd = g_clients[i].mosquitto_fd = -1; }
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) goto cleanup;
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(KEMTLS_PORT)};
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) goto cleanup;
    if (listen(server_fd, MAX_CLIENTS) < 0) goto cleanup;
    
    printf("[broker] Listening on port %d (mutual auth enabled)\n\n", KEMTLS_PORT);
    
    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        struct timeval timeout = {.tv_sec = 1};
        if (select(server_fd + 1, &read_fds, NULL, NULL, &timeout) <= 0) continue;
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) continue;
        
        pthread_mutex_lock(&g_clients_mutex);
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) if (!g_clients[i].active) { slot = i; break; }
        
        if (slot < 0) { close(client_fd); pthread_mutex_unlock(&g_clients_mutex); continue; }
        
        client_context_t *client = &g_clients[slot];
        client->client_fd = client_fd;
        client->client_addr = client_addr;
        client->active = 1;
        client->client_authenticated = false;
        client->ctx = kemtls_ctx_new(false);
        
        if (!client->ctx) { close(client_fd); client->active = 0; pthread_mutex_unlock(&g_clients_mutex); continue; }
        
        memcpy(client->ctx->server_kem_pk, g_broker_kem_pk, KYBER512_PK_BYTES);
        memcpy(client->ctx->server_kem_sk, g_broker_kem_sk, KYBER512_SK_BYTES);
        
        if (pthread_create(&client->thread, NULL, client_handler, client) != 0) {
            kemtls_ctx_free(client->ctx);
            close(client_fd);
            client->active = 0;
        } else pthread_detach(client->thread);
        
        pthread_mutex_unlock(&g_clients_mutex);
    }
    ret = 0;

cleanup:
    keystore_secure_wipe(g_broker_kem_pk, sizeof(g_broker_kem_pk));
    keystore_secure_wipe(g_broker_kem_sk, sizeof(g_broker_kem_sk));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&g_keystore);
    if (server_fd >= 0) close(server_fd);
    kemtls_cleanup();
    printf("[broker] Shutdown complete (keys wiped)\n");
    return ret;
}
