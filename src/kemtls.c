/*
 * kemtls.c - KEMTLS Protocol Implementation
 * 
 * Implementation of "Post-Quantum TLS Without Handshake Signatures"
 * Following the ACM CCS 2020 paper specification
 */

#include "kemtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Global KEM context
static OQS_KEM *g_kem = NULL;

// ============================================================================
// Library Initialization
// ============================================================================

int kemtls_init(void) {
    if (g_kem != NULL) return KEMTLS_OK;
    
    g_kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (g_kem == NULL) {
        fprintf(stderr, "Failed to initialize Kyber-512\n");
        return KEMTLS_ERR_KEYGEN;
    }
    
    printf("KEMTLS initialized (Kyber-512)\n");
    return KEMTLS_OK;
}

void kemtls_cleanup(void) {
    if (g_kem) {
        OQS_KEM_free(g_kem);
        g_kem = NULL;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

uint64_t kemtls_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int kemtls_random(uint8_t *buf, size_t len) {
    return RAND_bytes(buf, len) == 1 ? KEMTLS_OK : KEMTLS_ERR_GENERIC;
}

const char* kemtls_state_str(kemtls_state_t state) {
    switch (state) {
        case STATE_START: return "START";
        case STATE_WAIT_SERVER_HELLO: return "WAIT_SERVER_HELLO";
        case STATE_WAIT_ENCRYPTED_EXTENSIONS: return "WAIT_ENCRYPTED_EXTENSIONS";
        case STATE_WAIT_CERT: return "WAIT_CERT";
        case STATE_WAIT_SERVER_KEM_CTS: return "WAIT_SERVER_KEM_CTS";
        case STATE_WAIT_FINISHED: return "WAIT_FINISHED";
        case STATE_CONNECTED: return "CONNECTED";
        case STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

const char* kemtls_strerror(int err) {
    switch (err) {
        case KEMTLS_OK: return "Success";
        case KEMTLS_ERR_GENERIC: return "Generic error";
        case KEMTLS_ERR_NOMEM: return "Out of memory";
        case KEMTLS_ERR_INVALID_STATE: return "Invalid state";
        case KEMTLS_ERR_INVALID_MSG: return "Invalid message";
        case KEMTLS_ERR_KEYGEN: return "Key generation failed";
        case KEMTLS_ERR_ENCAPS: return "Encapsulation failed";
        case KEMTLS_ERR_DECAPS: return "Decapsulation failed";
        case KEMTLS_ERR_ENCRYPT: return "Encryption failed";
        case KEMTLS_ERR_DECRYPT: return "Decryption failed";
        case KEMTLS_ERR_VERIFY: return "Verification failed";
        case KEMTLS_ERR_KDF: return "Key derivation failed";
        default: return "Unknown error";
    }
}

// ============================================================================
// Context Management
// ============================================================================

kemtls_ctx_t* kemtls_ctx_new(bool is_client) {
    kemtls_ctx_t *ctx = calloc(1, sizeof(kemtls_ctx_t));
    if (!ctx) return NULL;
    
    ctx->is_client = is_client;
    ctx->state = STATE_START;
    
    // Generate client's ephemeral KEM keypair (if client)
    if (is_client) {
        if (OQS_KEM_keypair(g_kem, ctx->client_kem_pk, ctx->client_kem_sk) != OQS_SUCCESS) {
            free(ctx);
            return NULL;
        }
    }
    
    // Generate random values
    kemtls_random(ctx->client_random, RANDOM_LEN);
    if (!is_client) {
        kemtls_random(ctx->server_random, RANDOM_LEN);
    }
    
    ctx->handshake_start_ms = kemtls_time_ms();
    
    return ctx;
}

void kemtls_ctx_free(kemtls_ctx_t *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(kemtls_ctx_t));
        free(ctx);
    }
}

// ============================================================================
// HKDF-Extract and HKDF-Expand (TLS 1.3 Key Schedule)
// ============================================================================

static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t *prk) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return KEMTLS_ERR_KDF;
    
    int ret = KEMTLS_ERR_KDF;
    size_t out_len = 32;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0) goto cleanup;
    if (EVP_PKEY_derive(pctx, prk, &out_len) <= 0) goto cleanup;
    
    ret = KEMTLS_OK;
cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int hkdf_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return KEMTLS_ERR_KDF;
    
    int ret = KEMTLS_ERR_KDF;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) goto cleanup;
    
    size_t out_len = okm_len;
    if (EVP_PKEY_derive(pctx, okm, &out_len) <= 0) goto cleanup;
    
    ret = KEMTLS_OK;
cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

// ============================================================================
// TLS 1.3 Key Schedule for KEMTLS
// ============================================================================

int kemtls_derive_handshake_secrets(kemtls_ctx_t *ctx) {
    // Handshake Secret = HKDF-Extract(0, ss_c)
    uint8_t zeros[32] = {0};
    if (hkdf_extract(zeros, 32, ctx->ss_c, KYBER512_SS_BYTES, 
                     ctx->handshake_secret) != KEMTLS_OK) {
        return KEMTLS_ERR_KDF;
    }
    
    // Derive client handshake traffic secret
    const char *client_label = "c hs traffic";
    uint8_t client_secret[32];
    if (hkdf_expand(ctx->handshake_secret, 32,
                    (uint8_t *)client_label, strlen(client_label),
                    client_secret, 32) != KEMTLS_OK) {
        return KEMTLS_ERR_KDF;
    }
    
    // Derive server handshake traffic secret
    const char *server_label = "s hs traffic";
    uint8_t server_secret[32];
    if (hkdf_expand(ctx->handshake_secret, 32,
                    (uint8_t *)server_label, strlen(server_label),
                    server_secret, 32) != KEMTLS_OK) {
        return KEMTLS_ERR_KDF;
    }
    
    // Derive keys and IVs
    const char *key_label = "key";
    const char *iv_label = "iv";
    
    hkdf_expand(client_secret, 32, (uint8_t *)key_label, strlen(key_label),
                ctx->client_handshake_key, AEAD_KEY_LEN);
    hkdf_expand(client_secret, 32, (uint8_t *)iv_label, strlen(iv_label),
                ctx->client_handshake_iv, AEAD_IV_LEN);
    
    hkdf_expand(server_secret, 32, (uint8_t *)key_label, strlen(key_label),
                ctx->server_handshake_key, AEAD_KEY_LEN);
    hkdf_expand(server_secret, 32, (uint8_t *)iv_label, strlen(iv_label),
                ctx->server_handshake_iv, AEAD_IV_LEN);
    
    printf("✓ Derived handshake secrets\n");
    return KEMTLS_OK;
}

int kemtls_derive_master_secrets(kemtls_ctx_t *ctx) {
    // Master Secret = HKDF-Extract(handshake_secret, ss_s)
    if (hkdf_extract(ctx->handshake_secret, 32,
                     ctx->ss_s, KYBER512_SS_BYTES,
                     ctx->master_secret) != KEMTLS_OK) {
        return KEMTLS_ERR_KDF;
    }
    
    // Derive application traffic secrets
    const char *client_label = "c ap traffic";
    const char *server_label = "s ap traffic";
    
    uint8_t client_app_secret[32];
    uint8_t server_app_secret[32];
    
    hkdf_expand(ctx->master_secret, 32,
                (uint8_t *)client_label, strlen(client_label),
                client_app_secret, 32);
    hkdf_expand(ctx->master_secret, 32,
                (uint8_t *)server_label, strlen(server_label),
                server_app_secret, 32);
    
    // Derive application keys and IVs
    const char *key_label = "key";
    const char *iv_label = "iv";
    
    hkdf_expand(client_app_secret, 32, (uint8_t *)key_label, strlen(key_label),
                ctx->client_app_key, AEAD_KEY_LEN);
    hkdf_expand(client_app_secret, 32, (uint8_t *)iv_label, strlen(iv_label),
                ctx->client_app_iv, AEAD_IV_LEN);
    
    hkdf_expand(server_app_secret, 32, (uint8_t *)key_label, strlen(key_label),
                ctx->server_app_key, AEAD_KEY_LEN);
    hkdf_expand(server_app_secret, 32, (uint8_t *)iv_label, strlen(iv_label),
                ctx->server_app_iv, AEAD_IV_LEN);
    
    printf("✓ Derived application secrets\n");
    return KEMTLS_OK;
}

// ============================================================================
// AEAD Encryption/Decryption
// ============================================================================

static int aead_encrypt(const uint8_t *key, const uint8_t *iv, uint64_t seq,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t *ciphertext_len) {
    // Generate nonce: IV XOR sequence number
    uint8_t nonce[AEAD_IV_LEN];
    memcpy(nonce, iv, AEAD_IV_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[AEAD_IV_LEN - 1 - i] ^= (seq >> (i * 8)) & 0xFF;
    }
    
    EVP_CIPHER_CTX *ctx_cipher = EVP_CIPHER_CTX_new();
    if (!ctx_cipher) return KEMTLS_ERR_ENCRYPT;
    
    int len, ret = KEMTLS_ERR_ENCRYPT;
    
    if (EVP_EncryptInit_ex(ctx_cipher, EVP_aes_256_gcm(), NULL, key, nonce) != 1)
        goto cleanup;
    
    if (EVP_EncryptUpdate(ctx_cipher, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto cleanup;
    *ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx_cipher, ciphertext + len, &len) != 1)
        goto cleanup;
    *ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx_cipher, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN,
                            ciphertext + *ciphertext_len) != 1)
        goto cleanup;
    *ciphertext_len += AEAD_TAG_LEN;
    
    ret = KEMTLS_OK;
cleanup:
    EVP_CIPHER_CTX_free(ctx_cipher);
    return ret;
}

static int aead_decrypt(const uint8_t *key, const uint8_t *iv, uint64_t seq,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t *plaintext_len) {
    if (ciphertext_len < AEAD_TAG_LEN) return KEMTLS_ERR_DECRYPT;
    
    uint8_t nonce[AEAD_IV_LEN];
    memcpy(nonce, iv, AEAD_IV_LEN);
    for (int i = 0; i < 8; i++) {
        nonce[AEAD_IV_LEN - 1 - i] ^= (seq >> (i * 8)) & 0xFF;
    }
    
    size_t ct_len = ciphertext_len - AEAD_TAG_LEN;
    const uint8_t *tag = ciphertext + ct_len;
    
    EVP_CIPHER_CTX *ctx_cipher = EVP_CIPHER_CTX_new();
    if (!ctx_cipher) return KEMTLS_ERR_DECRYPT;
    
    int len, ret = KEMTLS_ERR_DECRYPT;
    
    if (EVP_DecryptInit_ex(ctx_cipher, EVP_aes_256_gcm(), NULL, key, nonce) != 1)
        goto cleanup;
    
    if (EVP_DecryptUpdate(ctx_cipher, plaintext, &len, ciphertext, ct_len) != 1)
        goto cleanup;
    *plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx_cipher, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LEN,
                            (void *)tag) != 1)
        goto cleanup;
    
    if (EVP_DecryptFinal_ex(ctx_cipher, plaintext + len, &len) != 1)
        goto cleanup;
    *plaintext_len += len;
    
    ret = KEMTLS_OK;
cleanup:
    EVP_CIPHER_CTX_free(ctx_cipher);
    return ret;
}

// ============================================================================
// Client Handshake Functions
// ============================================================================

int kemtls_client_hello(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    if (!ctx->is_client || ctx->state != STATE_START) {
        return KEMTLS_ERR_INVALID_STATE;
    }
    
    kemtls_client_hello_t *hello = (kemtls_client_hello_t *)out_buf;
    hello->version = htons(KEMTLS_VERSION);
    memcpy(hello->random, ctx->client_random, RANDOM_LEN);
    kemtls_random(hello->session_id, SESSION_ID_LEN);
    hello->cipher_suite = htons(TLS_KEMTLS_WITH_KYBER512_AES256GCM_SHA256);
    hello->legacy_compression = 0;
    
    ctx->state = STATE_WAIT_SERVER_HELLO;
    
    printf("→ ClientHello sent\n");
    return sizeof(kemtls_client_hello_t);
}

int kemtls_process_server_hello(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    if (ctx->state != STATE_WAIT_SERVER_HELLO) {
        return KEMTLS_ERR_INVALID_STATE;
    }
    
    const kemtls_server_hello_t *hello = (kemtls_server_hello_t *)msg;
    memcpy(ctx->server_random, hello->random, RANDOM_LEN);
    
    ctx->state = STATE_WAIT_ENCRYPTED_EXTENSIONS;
    
    printf("← ServerHello received\n");
    return KEMTLS_OK;
}

int kemtls_process_encrypted_extensions(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    // Decrypt using handshake keys (already derived from ss_c)
    uint8_t plaintext[1024];
    size_t plaintext_len;
    
    int ret = aead_decrypt(ctx->server_handshake_key, ctx->server_handshake_iv,
                          ctx->server_seq++, msg, len, plaintext, &plaintext_len);
    if (ret != KEMTLS_OK) return ret;
    
    ctx->state = STATE_WAIT_CERT;
    
    printf("← EncryptedExtensions received\n");
    return KEMTLS_OK;
}

int kemtls_process_certificate(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    // Decrypt certificate message
    uint8_t plaintext[MAX_CERT_LEN];
    size_t plaintext_len;
    
    int ret = aead_decrypt(ctx->server_handshake_key, ctx->server_handshake_iv,
                          ctx->server_seq++, msg, len, plaintext, &plaintext_len);
    if (ret != KEMTLS_OK) return ret;
    
    // Extract server's KEM public key from certificate
    memcpy(ctx->server_kem_pk, plaintext, KYBER512_PK_BYTES);
    
    ctx->state = STATE_WAIT_SERVER_KEM_CTS;
    
    printf("← Certificate received (KEM PK: %d bytes)\n", KYBER512_PK_BYTES);
    return KEMTLS_OK;
}

int kemtls_client_kem_encapsulation(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    if (ctx->state != STATE_WAIT_SERVER_KEM_CTS) {
        return KEMTLS_ERR_INVALID_STATE;
    }
    
    kemtls_kem_encapsulation_t *msg = (kemtls_kem_encapsulation_t *)out_buf;
    
    // Encapsulate to server's certificate KEM public key
    if (OQS_KEM_encaps(g_kem, msg->ciphertext, ctx->ss_c, ctx->server_kem_pk) != OQS_SUCCESS) {
        return KEMTLS_ERR_ENCAPS;
    }
    
    // Include client's ephemeral public key
    memcpy(msg->client_pk, ctx->client_kem_pk, KYBER512_PK_BYTES);
    
    // Derive handshake secrets now that we have ss_c
    kemtls_derive_handshake_secrets(ctx);
    
    printf("→ KEM Encapsulation sent (CT: %d + PK: %d bytes)\n",
           KYBER512_CT_BYTES, KYBER512_PK_BYTES);
    
    return sizeof(kemtls_kem_encapsulation_t);
}

int kemtls_process_server_kem_cts(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    const kemtls_server_kem_cts_t *kem_msg = (kemtls_server_kem_cts_t *)msg;
    
    // Decapsulate server's ciphertext with our ephemeral secret key
    if (OQS_KEM_decaps(g_kem, ctx->ss_s, kem_msg->ciphertext, ctx->client_kem_sk) != OQS_SUCCESS) {
        return KEMTLS_ERR_DECAPS;
    }
    
    // Derive master secrets now that we have both ss_c and ss_s
    kemtls_derive_master_secrets(ctx);
    
    ctx->state = STATE_WAIT_FINISHED;
    
    printf("← Server KEM ciphertext received\n");
    return KEMTLS_OK;
}

// ============================================================================
// Application Data
// ============================================================================

int kemtls_encrypt_data(kemtls_ctx_t *ctx,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t ciphertext_max) {
    if (ctx->state != STATE_CONNECTED) {
        return KEMTLS_ERR_INVALID_STATE;
    }
    
    size_t ciphertext_len;
    const uint8_t *key = ctx->is_client ? ctx->client_app_key : ctx->server_app_key;
    const uint8_t *iv = ctx->is_client ? ctx->client_app_iv : ctx->server_app_iv;
    uint64_t *seq = ctx->is_client ? &ctx->client_seq : &ctx->server_seq;
    
    int ret = aead_encrypt(key, iv, (*seq)++, plaintext, plaintext_len,
                          ciphertext, &ciphertext_len);
    
    if (ret == KEMTLS_OK) {
        ctx->bytes_sent += ciphertext_len;
    }
    
    return ret == KEMTLS_OK ? ciphertext_len : ret;
}

int kemtls_decrypt_data(kemtls_ctx_t *ctx,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *plaintext, size_t plaintext_max) {
    if (ctx->state != STATE_CONNECTED) {
        return KEMTLS_ERR_INVALID_STATE;
    }
    
    size_t plaintext_len;
    const uint8_t *key = ctx->is_client ? ctx->server_app_key : ctx->client_app_key;
    const uint8_t *iv = ctx->is_client ? ctx->server_app_iv : ctx->client_app_iv;
    uint64_t *seq = ctx->is_client ? &ctx->server_seq : &ctx->client_seq;
    
    int ret = aead_decrypt(key, iv, (*seq)++, ciphertext, ciphertext_len,
                          plaintext, &plaintext_len);
    
    if (ret == KEMTLS_OK) {
        ctx->bytes_received += plaintext_len;
    }
    
    return ret == KEMTLS_OK ? plaintext_len : ret;
}

// ============================================================================
// Server Handshake Functions (Implementations)
// ============================================================================

int kemtls_process_client_hello(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    const kemtls_client_hello_t *hello = (kemtls_client_hello_t *)msg;
    memcpy(ctx->client_random, hello->random, RANDOM_LEN);
    ctx->state = STATE_START;
    printf("← ClientHello received\n");
    return KEMTLS_OK;
}

int kemtls_server_hello(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    kemtls_server_hello_t *hello = (kemtls_server_hello_t *)out_buf;
    hello->version = htons(KEMTLS_VERSION);
    memcpy(hello->random, ctx->server_random, RANDOM_LEN);
    kemtls_random(hello->session_id, SESSION_ID_LEN);
    hello->cipher_suite = htons(TLS_KEMTLS_WITH_KYBER512_AES256GCM_SHA256);
    hello->legacy_compression = 0;
    
    printf("→ ServerHello sent\n");
    return sizeof(kemtls_server_hello_t);
}

int kemtls_server_encrypted_extensions(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    // Empty extensions for now
    out_buf[0] = 0;
    
    printf("→ EncryptedExtensions sent\n");
    return 1;
}

int kemtls_server_certificate(kemtls_ctx_t *ctx,
                              const kemtls_certificate_t *cert,
                              uint8_t *out_buf, size_t out_len) {
    // Pack certificate (simplified - just the KEM public key)
    memcpy(out_buf, cert->pk_kem, KYBER512_PK_BYTES);
    
    // Store server's key in context
    memcpy(ctx->server_kem_pk, cert->pk_kem, KYBER512_PK_BYTES);
    
    printf("→ Certificate sent (KEM PK: %d bytes)\n", KYBER512_PK_BYTES);
    return KYBER512_PK_BYTES;
}

int kemtls_process_client_kem_encaps(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    const kemtls_kem_encapsulation_t *kem_msg = (kemtls_kem_encapsulation_t *)msg;
    
    // Decapsulate with our certificate secret key
 	if (OQS_KEM_decaps(g_kem, ctx->ss_c, kem_msg->ciphertext, ctx->server_kem_sk) != OQS_SUCCESS) {
    	 fprintf(stderr, "Decapsulation failed!\n");
    	 return KEMTLS_ERR_DECAPS;
}
    
    // Extract client's ephemeral public key
    memcpy(ctx->client_kem_pk, kem_msg->client_pk, KYBER512_PK_BYTES);
    
    // Derive handshake secrets
    kemtls_derive_handshake_secrets(ctx);
    
    printf("← KEM Encapsulation received\n");
    return KEMTLS_OK;
}

int kemtls_server_kem_cts(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    kemtls_server_kem_cts_t *msg = (kemtls_server_kem_cts_t *)out_buf;
    
    // Encapsulate to client's ephemeral public key
    if (OQS_KEM_encaps(g_kem, msg->ciphertext, ctx->ss_s, ctx->client_kem_pk) != OQS_SUCCESS) {
        return KEMTLS_ERR_ENCAPS;
    }
    
    // Derive master secrets
    kemtls_derive_master_secrets(ctx);
    
    printf("→ Server KEM CTS sent\n");
    return sizeof(kemtls_server_kem_cts_t);
}

int kemtls_server_finished(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    kemtls_finished_t *finished = (kemtls_finished_t *)out_buf;
    
    // Compute verify_data = HMAC(transcript_hash)
    // Simplified: just hash of handshake
    SHA256(ctx->transcript_hash, ctx->transcript_len, finished->verify_data);
    
    ctx->state = STATE_CONNECTED;
    ctx->handshake_complete_ms = kemtls_time_ms();
    
    printf("→ Server Finished sent\n");
    return sizeof(kemtls_finished_t);
}

int kemtls_process_client_finished(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    (void)msg;
    (void)len;
    
    printf("← Client Finished received\n");
    return KEMTLS_OK;
}

int kemtls_client_finished(kemtls_ctx_t *ctx, uint8_t *out_buf, size_t out_len) {
    kemtls_finished_t *finished = (kemtls_finished_t *)out_buf;
    
    // Compute verify_data
    SHA256(ctx->transcript_hash, ctx->transcript_len, finished->verify_data);
    
    printf("→ Client Finished sent\n");
    return sizeof(kemtls_finished_t);
}

int kemtls_process_server_finished(kemtls_ctx_t *ctx, const uint8_t *msg, size_t len) {
    (void)msg;
    (void)len;
    
    ctx->state = STATE_CONNECTED;
    ctx->handshake_complete_ms = kemtls_time_ms();
    
    printf("← Server Finished received\n");
    return KEMTLS_OK;
}

// ============================================================================
// Certificate Management
// ============================================================================

int kemtls_load_certificate(kemtls_certificate_t *cert,
                            const char *subject,
                            const uint8_t *kem_pk) {
    strncpy((char *)cert->subject, subject, sizeof(cert->subject));
    memcpy(cert->pk_kem, kem_pk, KYBER512_PK_BYTES);
    cert->cert_len = 0;
    return KEMTLS_OK;
}

int kemtls_verify_certificate(const kemtls_certificate_t *cert) {
    // Simplified: always accept
    return KEMTLS_OK;
}

// ============================================================================
// Statistics
// ============================================================================

uint64_t kemtls_get_handshake_time(const kemtls_ctx_t *ctx) {
    if (ctx->state != STATE_CONNECTED) return 0;
    return ctx->handshake_complete_ms - ctx->handshake_start_ms;
}

void kemtls_print_stats(const kemtls_ctx_t *ctx) {
    printf("\n=== KEMTLS Connection Statistics ===\n");
    printf("Role: %s\n", ctx->is_client ? "Client" : "Server");
    printf("State: %s\n", kemtls_state_str(ctx->state));
    
    if (ctx->state == STATE_CONNECTED) {
        printf("Handshake time: %lu ms\n", kemtls_get_handshake_time(ctx));
        printf("Bytes sent: %lu\n", ctx->bytes_sent);
        printf("Bytes received: %lu\n", ctx->bytes_received);
    }
    
    printf("====================================\n\n");
}
