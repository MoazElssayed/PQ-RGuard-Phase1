/*
 * secure_keystore.h - Secure Key Storage for PQ-RGuard
 * 
 * Provides encrypted storage for cryptographic keys at rest.
 * Keys encrypted with AES-256-GCM, derived via PBKDF2.
 */

#ifndef SECURE_KEYSTORE_H
#define SECURE_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef KYBER512_PK_BYTES
#define KYBER512_PK_BYTES 800
#endif
#ifndef KYBER512_SK_BYTES
#define KYBER512_SK_BYTES 1632
#endif

#define KEYSTORE_SALT_SIZE      16
#define KEYSTORE_IV_SIZE        12
#define KEYSTORE_TAG_SIZE       16
#define KEYSTORE_PBKDF2_ITER    100000
#define MAX_TRUSTED_CLIENTS     32

#define KEYSTORE_OK              0
#define KEYSTORE_ERR_FILE       -1
#define KEYSTORE_ERR_CRYPTO     -2
#define KEYSTORE_ERR_MEMORY     -3
#define KEYSTORE_ERR_INVALID    -4
#define KEYSTORE_ERR_AUTH       -5

typedef enum {
    KEYTYPE_BROKER_PUBLIC,
    KEYTYPE_BROKER_SECRET,
    KEYTYPE_CLIENT_PUBLIC,
    KEYTYPE_CLIENT_SECRET,
    KEYTYPE_TRUSTED_CLIENTS,
    KEYTYPE_TRUSTED_BROKER
} keystore_type_t;

typedef struct {
    char device_id[64];
    char keystore_path[256];
    uint8_t master_key[32];
    bool initialized;
} keystore_ctx_t;

int keystore_init(keystore_ctx_t *ctx, const char *device_id,
                  const char *keystore_path, const char *password);
int keystore_store_key(keystore_ctx_t *ctx, keystore_type_t key_type,
                       const uint8_t *key_data, size_t key_size);
int keystore_load_key(keystore_ctx_t *ctx, keystore_type_t key_type,
                      uint8_t *key_data, size_t *key_size);
int keystore_store_trusted_clients(keystore_ctx_t *ctx, const uint8_t *client_keys,
                                   size_t key_size, size_t num_clients);
int keystore_load_trusted_clients(keystore_ctx_t *ctx, uint8_t *client_keys,
                                  size_t key_size, size_t max_clients, size_t *num_clients);
bool keystore_is_client_trusted(keystore_ctx_t *ctx, const uint8_t *client_pk, size_t key_size);
void keystore_secure_wipe(void *ptr, size_t size);
void keystore_cleanup(keystore_ctx_t *ctx);
int keystore_get_device_secret(uint8_t *secret, size_t size);

#endif
