/*
 * kemtls_broker_enhanced.c - Enhanced KEMTLS Broker with Real MQTT Forwarding
 * 
 * Compile:
 *   gcc -o kemtls_broker_enhanced kemtls_broker_enhanced.c kemtls.c \
 *       kemtls_metrics.c mqtt_protocol.c -I. -loqs -lssl -lcrypto -lpthread
 */

#include "kemtls.h"
#include "kemtls_metrics.h"
#include "mqtt_protocol.h"
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
#include <oqs/oqs.h>

#define KEMTLS_PORT 8884
#define MOSQUITTO_HOST "127.0.0.1"
#define MOSQUITTO_PORT 1883
#define MAX_CLIENTS 10
#define BUFFER_SIZE 8192

static volatile int g_running = 1;

// Broker's certificate keys
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
} client_context_t;

static client_context_t g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    printf("\nShutting down broker...\n");
    g_running = 0;
}

// Load broker keys
int load_broker_keys(void) {
    FILE *pk_file = fopen("broker_cert.pk", "rb");
    FILE *sk_file = fopen("broker_cert.sk", "rb");
    
    if (pk_file && sk_file) {
        fread(g_broker_kem_pk, 1, KYBER512_PK_BYTES, pk_file);
        fread(g_broker_kem_sk, 1, KYBER512_SK_BYTES, sk_file);
        fclose(pk_file);
        fclose(sk_file);
        printf("✓ Loaded broker certificate keys\n");
    } else {
        printf("Generating new broker certificate keys...\n");
        
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if (!kem || OQS_KEM_keypair(kem, g_broker_kem_pk, g_broker_kem_sk) != OQS_SUCCESS) {
            if (kem) OQS_KEM_free(kem);
            return -1;
        }
        OQS_KEM_free(kem);
        
        pk_file = fopen("broker_cert.pk", "wb");
        sk_file = fopen("broker_cert.sk", "wb");
        if (pk_file && sk_file) {
            fwrite(g_broker_kem_pk, 1, KYBER512_PK_BYTES, pk_file);
            fwrite(g_broker_kem_sk, 1, KYBER512_SK_BYTES, sk_file);
            fclose(pk_file);
            fclose(sk_file);
            printf("✓ Generated and saved broker certificate keys\n");
        }
    }
    
    return 0;
}

// Send/recv functions
int send_handshake_msg(int sock, uint8_t msg_type, const uint8_t *data, size_t len) {
    uint8_t frame[4];
    frame[0] = msg_type;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    
    if (send(sock, frame, 4, 0) != 4) return -1;
    if (len > 0 && send(sock, data, len, 0) != (ssize_t)len) return -1;
    
    return 0;
}

int recv_handshake_msg(int sock, uint8_t *msg_type, uint8_t *data, size_t *len) {
    uint8_t frame[4];
    
    if (recv(sock, frame, 4, MSG_WAITALL) != 4) return -1;
    
    *msg_type = frame[0];
    *len = (frame[1] << 16) | (frame[2] << 8) | frame[3];
    
    if (*len > BUFFER_SIZE) return -1;
    if (*len > 0 && recv(sock, data, *len, MSG_WAITALL) != (ssize_t)*len) return -1;
    
    return 0;
}

// Connect to Mosquitto
int connect_to_mosquitto(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MOSQUITTO_PORT);
    inet_pton(AF_INET, MOSQUITTO_HOST, &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect to mosquitto");
        close(fd);
        return -1;
    }
    
    printf("  ✓ Connected to Mosquitto at %s:%d\n", MOSQUITTO_HOST, MOSQUITTO_PORT);
    return fd;
}

// Server handshake (same as before, but with metrics)
int perform_server_handshake(client_context_t *client) {
    uint8_t buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    int ret;
    kemtls_ctx_t *ctx = client->ctx;
    int sock = client->client_fd;
    
    printf("  [Client %d] Starting KEMTLS handshake\n", client->slot);
    
    METRICS_START_TIMER(total);
    
    // ========== PAPER'S LTLS TIMER (Server Perspective) ==========
    uint64_t ltls_start = kemtls_time_ms();
    
    // 1. ClientHello
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_CLIENT_HELLO) return -1;
    ret = kemtls_process_client_hello(ctx, buffer, msg_len);
    if (ret != KEMTLS_OK) return -1;
    
    // 2. ServerHello
    ret = kemtls_server_hello(ctx, buffer, sizeof(buffer));
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_SERVER_HELLO, buffer, ret) != 0) return -1;
    
    // ========== STOP PAPER'S TIMER HERE ==========
	uint64_t ltls_end = kemtls_time_ms();
	uint64_t ltls_broker_ms = ltls_end - ltls_start;
	printf("  [Client %d] 📊 Broker LTLS: %lu ms\n", 
       client->slot, ltls_broker_ms);
    // ============================================
    
    // 3. EncryptedExtensions
    ret = kemtls_server_encrypted_extensions(ctx, buffer, sizeof(buffer));
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_ENCRYPTED_EXTENSIONS, buffer, ret) != 0) return -1;
    
    // 4. Certificate
    kemtls_certificate_t cert;
    strncpy((char *)cert.subject, "broker.local", sizeof(cert.subject));
    memcpy(cert.pk_kem, g_broker_kem_pk, KYBER512_PK_BYTES);
    
    ret = kemtls_server_certificate(ctx, &cert, buffer, sizeof(buffer));
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_CERTIFICATE, buffer, ret) != 0) return -1;
    
    // 5. Client KEM Encapsulation
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_KEM_ENCAPSULATION) return -1;
    ret = kemtls_process_client_kem_encaps(ctx, buffer, msg_len);
    if (ret != KEMTLS_OK) return -1;
    
    // 6. Server KEM CTS
    ret = kemtls_server_kem_cts(ctx, buffer, sizeof(buffer));
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_SERVER_KEM_CTS, buffer, ret) != 0) return -1;
    
    // 7. Client Finished
    if (recv_handshake_msg(sock, &msg_type, buffer, &msg_len) != 0) return -1;
    if (msg_type != KEMTLS_FINISHED) return -1;
    ret = kemtls_process_client_finished(ctx, buffer, msg_len);
    if (ret != KEMTLS_OK) return -1;
    
    // 8. Server Finished
    ret = kemtls_server_finished(ctx, buffer, sizeof(buffer));
    if (ret < 0) return -1;
    if (send_handshake_msg(sock, KEMTLS_FINISHED, buffer, ret) != 0) return -1;
    
    METRICS_END_TIMER(total, &client->metrics, total_handshake_us);
    client->metrics.num_handshakes++;
    
    printf("  [Client %d] ✓ KEMTLS handshake complete (%.2f ms full)\n",
           client->slot, client->metrics.total_handshake_us / 1000.0);
    
    return 0;
}

// Client handler thread
void *client_handler(void *arg) {
    client_context_t *client = (client_context_t *)arg;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->client_addr.sin_addr, client_ip, sizeof(client_ip));
    
    printf("\n[Client %d] Connection from %s:%d\n",
           client->slot, client_ip, ntohs(client->client_addr.sin_port));
    
    // Initialize metrics
    kemtls_metrics_init(&client->metrics);
    
    // Handshake
    if (perform_server_handshake(client) != 0) {
        fprintf(stderr, "[Client %d] Handshake failed\n", client->slot);
        goto cleanup;
    }
    
    // Connect to Mosquitto
    client->mosquitto_fd = connect_to_mosquitto();
    if (client->mosquitto_fd < 0) {
        fprintf(stderr, "[Client %d] Failed to connect to Mosquitto\n", client->slot);
        goto cleanup;
    }
    
    printf("[Client %d] Proxying MQTT traffic...\n", client->slot);
    
    // Proxy loop
    uint8_t recv_buffer[BUFFER_SIZE];
    uint8_t plain_buffer[BUFFER_SIZE];
    uint8_t encrypted_buffer[BUFFER_SIZE];
    uint8_t msg_type;
    size_t msg_len;
    
    while (client->active && g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client->client_fd, &read_fds);
        FD_SET(client->mosquitto_fd, &read_fds);
        
        int max_fd = (client->client_fd > client->mosquitto_fd) ? 
                     client->client_fd : client->mosquitto_fd;
        
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (activity == 0) continue;
        
        // Data from client (encrypted MQTT)
        if (FD_ISSET(client->client_fd, &read_fds)) {
            if (recv_handshake_msg(client->client_fd, &msg_type, recv_buffer, &msg_len) != 0) {
                printf("[Client %d] Connection closed\n", client->slot);
                break;
            }
            
            if (msg_type == KEMTLS_APPLICATION_DATA) {
                // Decrypt
                METRICS_START_TIMER(dec);
                int ret = kemtls_decrypt_data(client->ctx, recv_buffer, msg_len,
                                             plain_buffer, sizeof(plain_buffer));
                METRICS_END_TIMER(dec, &client->metrics, decryption_time_us);
                
                if (ret >= 0) {
                    size_t plain_len = ret;
                    client->metrics.num_decrypted_msgs++;
                    
                    printf("[Client %d] Decrypted %zu bytes MQTT packet\n",
                           client->slot, plain_len);
                    
                    // Forward to Mosquitto
                    if (send(client->mosquitto_fd, plain_buffer, plain_len, 0) != (ssize_t)plain_len) {
                        fprintf(stderr, "[Client %d] Failed to forward to Mosquitto\n", client->slot);
                        break;
                    }
                    
                    printf("[Client %d] ✓ Forwarded to Mosquitto\n", client->slot);
                } else {
                    fprintf(stderr, "[Client %d] Decryption failed\n", client->slot);
                    break;
                }
            }
        }
        
        // Data from Mosquitto (plaintext MQTT response)
        if (FD_ISSET(client->mosquitto_fd, &read_fds)) {
            ssize_t n = recv(client->mosquitto_fd, plain_buffer, sizeof(plain_buffer), 0);
            if (n <= 0) {
                printf("[Client %d] Mosquitto connection closed\n", client->slot);
                break;
            }
            
            printf("[Client %d] Received %zd bytes from Mosquitto\n", client->slot, n);
            
            // Encrypt
            METRICS_START_TIMER(enc);
            int ret = kemtls_encrypt_data(client->ctx, plain_buffer, n,
                                         encrypted_buffer, sizeof(encrypted_buffer));
            METRICS_END_TIMER(enc, &client->metrics, encryption_time_us);
            
            if (ret >= 0) {
                size_t encrypted_len = ret;
                client->metrics.num_encrypted_msgs++;
                
                // Send to client
                if (send_handshake_msg(client->client_fd, KEMTLS_APPLICATION_DATA,
                                      encrypted_buffer, encrypted_len) != 0) {
                    fprintf(stderr, "[Client %d] Failed to send to client\n", client->slot);
                    break;
                }
                
                printf("[Client %d] ✓ Encrypted and sent %zu bytes to client\n",
                       client->slot, encrypted_len);
            }
        }
    }

cleanup:
    printf("[Client %d] Session ending\n", client->slot);
    
    // Print client metrics
    if (client->metrics.num_handshakes > 0) {
        kemtls_metrics_print(&client->metrics, "Broker Client Session");
    }
    
    if (client->client_fd >= 0) {
        close(client->client_fd);
        client->client_fd = -1;
    }
    
    if (client->mosquitto_fd >= 0) {
        close(client->mosquitto_fd);
        client->mosquitto_fd = -1;
    }
    
    if (client->ctx) {
        kemtls_ctx_free(client->ctx);
        client->ctx = NULL;
    }
    
    pthread_mutex_lock(&g_clients_mutex);
    client->active = 0;
    pthread_mutex_unlock(&g_clients_mutex);
    
    return NULL;
}

int main(void) {
    int server_fd = -1;
    int ret = 1;
    
    printf("   KEMTLS Enhanced Broker - Raspberry Pi 5                   \n");
    printf("║   With Real MQTT Forwarding & Metrics                       \n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize KEMTLS
    if (kemtls_init() != KEMTLS_OK) {
        fprintf(stderr, "KEMTLS init failed\n");
        return 1;
    }
    
    // Load broker keys
    if (load_broker_keys() != 0) {
        fprintf(stderr, "Failed to load broker keys\n");
        goto cleanup;
    }
    
    // Initialize client array
    memset(g_clients, 0, sizeof(g_clients));
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].slot = i;
        g_clients[i].client_fd = -1;
        g_clients[i].mosquitto_fd = -1;
    }
    
    // Create listening socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        goto cleanup;
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(KEMTLS_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        goto cleanup;
    }
    
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        goto cleanup;
    }
    
    printf("✓ Listening on port %d\n", KEMTLS_PORT);
    printf("✓ Forwarding to Mosquitto at %s:%d\n", MOSQUITTO_HOST, MOSQUITTO_PORT);
    printf("✓ Ready for connections (max: %d)\n\n", MAX_CLIENTS);
    
    // Accept loop
    while (g_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        int activity = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (activity == 0) continue;
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        
        // Find free slot
        pthread_mutex_lock(&g_clients_mutex);
        
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_clients[i].active == 0) {
                slot = i;
                break;
            }
        }
        
        if (slot < 0) {
            printf("✗ Max clients reached, rejecting\n");
            close(client_fd);
            pthread_mutex_unlock(&g_clients_mutex);
            continue;
        }
        
        client_context_t *client = &g_clients[slot];
        client->client_fd = client_fd;
        client->client_addr = client_addr;
        client->active = 1;
        
        // Create server context
        client->ctx = kemtls_ctx_new(false);
        if (!client->ctx) {
            fprintf(stderr, "Failed to create context\n");
            close(client_fd);
            client->active = 0;
            pthread_mutex_unlock(&g_clients_mutex);
            continue;
        }
        
        // Copy broker's keys to context
        memcpy(client->ctx->server_kem_pk, g_broker_kem_pk, KYBER512_PK_BYTES);
        memcpy(client->ctx->server_kem_sk, g_broker_kem_sk, KYBER512_SK_BYTES);
        
        // Create handler thread
        if (pthread_create(&client->thread, NULL, client_handler, client) != 0) {
            perror("pthread_create");
            kemtls_ctx_free(client->ctx);
            close(client_fd);
            client->active = 0;
        } else {
            pthread_detach(client->thread);
        }
        
        pthread_mutex_unlock(&g_clients_mutex);
    }
    
    printf("\nWaiting for clients to disconnect...\n");
    sleep(2);
    
    ret = 0;

cleanup:
    if (server_fd >= 0) close(server_fd);
    kemtls_cleanup();
    
    printf("\n✓ Broker shutdown complete\n");
    return ret;
}
