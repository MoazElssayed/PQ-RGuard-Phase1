/*
 * kemtls.h - KEMTLS Protocol Implementation
 * 
 * Based on: "Post-Quantum TLS Without Handshake Signatures"
 * by Schwabe, Stebila, and Wiggers (ACM CCS 2020)
 */

#ifndef KEMTLS_H
#define KEMTLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

// ============================================================================
// Protocol Constants
// ============================================================================

#define KEMTLS_VERSION 0x0304  // TLS 1.3 = 0x0304

// Kyber-512 parameters
#define KYBER512_PK_BYTES   800
#define KYBER512_SK_BYTES   1632
#define KYBER512_CT_BYTES   768
#define KYBER512_SS_BYTES   32

// Cipher suite parameters
#define AEAD_KEY_LEN        32   // AES-256
#define AEAD_IV_LEN         12   // GCM IV
#define AEAD_TAG_LEN        16   // GCM tag

// Handshake constants
#define RANDOM_LEN          32
#define SESSION_ID_LEN      32
#define MAX_CERT_LEN        4096
#define MAX_HANDSHAKE_LEN   8192

// KEMTLS message types (handshake)
#define KEMTLS_CLIENT_HELLO         0x01
#define KEMTLS_SERVER_HELLO         0x02
#define KEMTLS_ENCRYPTED_EXTENSIONS 0x08
#define KEMTLS_CERTIFICATE          0x0B
#define KEMTLS_KEM_ENCAPSULATION    0x0F
#define KEMTLS_SERVER_KEM_CTS       0x10
#define KEMTLS_FINISHED             0x14
#define KEMTLS_APPLICATION_DATA     0x17

// Cipher suites
#define TLS_KEMTLS_WITH_KYBER512_AES256GCM_SHA256  0x1301

// ============================================================================
// KEMTLS State Machine
// ============================================================================

typedef enum {
    STATE_START = 0,
    STATE_WAIT_SERVER_HELLO,
    STATE_WAIT_ENCRYPTED_EXTENSIONS,
    STATE_WAIT_CERT,
    STATE_WAIT_SERVER_KEM_CTS,
    STATE_WAIT_FINISHED,
    STATE_CONNECTED,
    STATE_ERROR
} kemtls_state_t;

// ============================================================================
// Certificate Structure
// ============================================================================

typedef struct {
    uint8_t subject[256];
    uint8_t pk_kem[KYBER512_PK_BYTES];
    uint16_t cert_len;
    uint8_t cert_data[MAX_CERT_LEN];
} kemtls_certificate_t;

// ============================================================================
// KEMTLS Connection Context
// ============================================================================

typedef struct {
    bool is_client;
    kemtls_state_t state;
    
    uint8_t client_random[RANDOM_LEN];
    uint8_t server_random[RANDOM_LEN];
    
    uint8_t client_kem_pk[KYBER512_PK_BYTES];
    uint8_t client_kem_sk[KYBER512_SK_BYTES];
    
    uint8_t server_kem_pk[KYBER512_PK_BYTES];
    uint8_t server_kem_sk[KYBER512_SK_BYTES];
    
    uint8_t ss_c[KYBER512_SS_BYTES];
    uint8_t ss_s[KYBER512_SS_BYTES];
    
    uint8_t handshake_secret[32];
    uint8_t client_handshake_key[AEAD_KEY_LEN];
    uint8_t client_handshake_iv[AEAD_IV_LEN];
    uint8_t server_handshake_key[AEAD_KEY_LEN];
    uint8_t server_handshake_iv[AEAD_IV_LEN];
    
    uint8_t master_secret[32];
    uint8_t client_app_key[AEAD_KEY_LEN];
    uint8_t client_app_iv[AEAD_IV_LEN];
    uint8_t server_app_key[AEAD_KEY_LEN];
    uint8_t server_app_iv[AEAD_IV_LEN];
    
    uint8_t transcript_hash[32];
    size_t transcript_len;
    
    uint64_t client_seq;
    uint64_t server_seq;
    
    kemtls_certificate_t server_cert;
    
    uint64_t handshake_start_ms;
    uint64_t handshake_complete_ms;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
} kemtls_ctx_t;

// ============================================================================
// Handshake Message Structures
// ============================================================================

typedef struct {
    uint16_t version;
    uint8_t random[RANDOM_LEN];
    uint8_t session_id[SESSION_ID_LEN];
    uint16_t cipher_suite;
    uint8_t legacy_compression;
} kemtls_client_hello_t;

typedef struct {
    uint16_t version;
    uint8_t random[RANDOM_LEN];
    uint8_t session_id[SESSION_ID_LEN];
    uint16_t cipher_suite;
    uint8_t legacy_compression;
} kemtls_server_hello_t;

typedef struct {
    uint8_t ciphertext[KYBER512_CT_BYTES];
    uint8_t client_pk[KYBER512_PK_BYTES];
} kemtls_kem_encapsulation_t;

typedef struct {
    uint8_t ciphertext[KYBER512_CT_BYTES];
} kemtls_server_kem_cts_t;

typedef struct {
    uint8_t verify_data[32];
} kemtls_finished_t;

// ============================================================================
// Core API Functions
// ============================================================================

int kemtls_init(void);
void kemtls_cleanup(void);
kemtls_ctx_t* kemtls_ctx_new(bool is_client);
void kemtls_ctx_free(kemtls_ctx_t *ctx);

// Client-side
int kemtls_client_hello(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_process_server_hello(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_process_encrypted_extensions(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_process_certificate(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_client_kem_encapsulation(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_process_server_kem_cts(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_client_finished(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_process_server_finished(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);

// Server-side
int kemtls_process_client_hello(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_server_hello(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_server_encrypted_extensions(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_server_certificate(kemtls_ctx_t *ctx, const kemtls_certificate_t *cert, uint8_t *out_buf, size_t out_len);
int kemtls_process_client_kem_encaps(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);
int kemtls_server_kem_cts(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_server_finished(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len);
int kemtls_process_client_finished(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len);

// Application data
int kemtls_encrypt_data(kemtls_ctx_t *ctx, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_max);
int kemtls_decrypt_data(kemtls_ctx_t *ctx, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t plaintext_max);

// Key derivation
int kemtls_derive_handshake_secrets(kemtls_ctx_t *ctx);
int kemtls_derive_master_secrets(kemtls_ctx_t *ctx);

// Certificate
int kemtls_load_certificate(kemtls_certificate_t *cert, const char *subject, const uint8_t *kem_pk);
int kemtls_verify_certificate(const kemtls_certificate_t *cert);

// Utility
uint64_t kemtls_time_ms(void);
int kemtls_random(uint8_t *buf, size_t len);
uint64_t kemtls_get_handshake_time(const kemtls_ctx_t *ctx);
const char* kemtls_state_str(kemtls_state_t state);
void kemtls_print_stats(const kemtls_ctx_t *ctx);

// Error codes
#define KEMTLS_OK                    0
#define KEMTLS_ERR_GENERIC          -1
#define KEMTLS_ERR_NOMEM            -2
#define KEMTLS_ERR_INVALID_STATE    -3
#define KEMTLS_ERR_INVALID_MSG      -4
#define KEMTLS_ERR_KEYGEN           -5
#define KEMTLS_ERR_ENCAPS           -6
#define KEMTLS_ERR_DECAPS           -7
#define KEMTLS_ERR_ENCRYPT          -8
#define KEMTLS_ERR_DECRYPT          -9
#define KEMTLS_ERR_VERIFY           -10
#define KEMTLS_ERR_KDF              -11

const char* kemtls_strerror(int err);

#endif // KEMTLS_H
