/*
 * secure_keystore.c - Secure Key Storage Implementation
 * Compile with: -lssl -lcrypto
 */

#include "secure_keystore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

static const uint8_t KEYSTORE_MAGIC[4] = {'P', 'Q', 'R', 'G'};
static const uint8_t KEYSTORE_VERSION = 0x01;

static uint8_t g_trusted_client_keys[MAX_TRUSTED_CLIENTS][KYBER512_PK_BYTES];
static size_t g_num_trusted_clients = 0;
static bool g_trusted_clients_loaded = false;

void keystore_secure_wipe(void *ptr, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (size--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
}

static const char* get_key_filename(keystore_type_t key_type) {
    switch (key_type) {
        case KEYTYPE_BROKER_PUBLIC:    return "broker_pub.enc";
        case KEYTYPE_BROKER_SECRET:    return "broker_sec.enc";
        case KEYTYPE_CLIENT_PUBLIC:    return "client_pub.enc";
        case KEYTYPE_CLIENT_SECRET:    return "client_sec.enc";
        case KEYTYPE_TRUSTED_CLIENTS:  return "trusted_clients.enc";
        case KEYTYPE_TRUSTED_BROKER:   return "trusted_broker.enc";
        default:                       return "unknown.enc";
    }
}

int keystore_get_device_secret(uint8_t *secret, size_t size) {
    if (size < 32) return KEYSTORE_ERR_MEMORY;
    memset(secret, 0, size);
    
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Serial", 6) == 0) {
                char *serial = strchr(line, ':');
                if (serial) {
                    serial++;
                    while (*serial == ' ') serial++;
                    size_t len = strlen(serial);
                    if (len > 0 && serial[len-1] == '\n') len--;
                    if (len > 16) len = 16;
                    memcpy(secret, serial, len);
                }
                break;
            }
        }
        fclose(f);
    }
    
    f = fopen("/sys/block/mmcblk0/device/cid", "r");
    if (f) {
        char cid[64];
        if (fgets(cid, sizeof(cid), f)) {
            size_t len = strlen(cid);
            if (len > 0 && cid[len-1] == '\n') len--;
            if (len > 16) len = 16;
            memcpy(secret + 16, cid, len);
        }
        fclose(f);
    }
    
    if (secret[0] == 0) {
        f = fopen("/etc/machine-id", "r");
        if (f) {
            fread(secret, 1, 32, f);
            fclose(f);
        }
    }
    return KEYSTORE_OK;
}

int keystore_init(keystore_ctx_t *ctx, const char *device_id,
                  const char *keystore_path, const char *password) {
    if (!ctx || !device_id || !keystore_path || !password) return KEYSTORE_ERR_INVALID;
    
    memset(ctx, 0, sizeof(keystore_ctx_t));
    strncpy(ctx->device_id, device_id, sizeof(ctx->device_id) - 1);
    strncpy(ctx->keystore_path, keystore_path, sizeof(ctx->keystore_path) - 1);
    mkdir(keystore_path, 0700);
    
    uint8_t device_secret[32];
    if (keystore_get_device_secret(device_secret, sizeof(device_secret)) != KEYSTORE_OK)
        return KEYSTORE_ERR_CRYPTO;
    
    size_t combined_len = strlen(password) + sizeof(device_secret);
    uint8_t *combined = malloc(combined_len);
    if (!combined) return KEYSTORE_ERR_MEMORY;
    
    memcpy(combined, password, strlen(password));
    memcpy(combined + strlen(password), device_secret, sizeof(device_secret));
    
    uint8_t salt[KEYSTORE_SALT_SIZE];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, device_id, strlen(device_id));
    EVP_DigestUpdate(md_ctx, "PQRGUARD_KEYSTORE", 17);
    unsigned int salt_len;
    EVP_DigestFinal_ex(md_ctx, salt, &salt_len);
    EVP_MD_CTX_free(md_ctx);
    
    if (PKCS5_PBKDF2_HMAC((const char *)combined, combined_len, salt, KEYSTORE_SALT_SIZE,
                          KEYSTORE_PBKDF2_ITER, EVP_sha256(), 32, ctx->master_key) != 1) {
        keystore_secure_wipe(combined, combined_len);
        free(combined);
        return KEYSTORE_ERR_CRYPTO;
    }
    
    keystore_secure_wipe(combined, combined_len);
    keystore_secure_wipe(device_secret, sizeof(device_secret));
    free(combined);
    ctx->initialized = true;
    
    printf("[keystore] Initialized (PBKDF2: %d iterations, device-bound)\n", KEYSTORE_PBKDF2_ITER);
    return KEYSTORE_OK;
}

int keystore_store_key(keystore_ctx_t *ctx, keystore_type_t key_type,
                       const uint8_t *key_data, size_t key_size) {
    if (!ctx || !ctx->initialized || !key_data || key_size == 0) return KEYSTORE_ERR_INVALID;
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", ctx->keystore_path, get_key_filename(key_type));
    
    uint8_t iv[KEYSTORE_IV_SIZE], salt[KEYSTORE_SALT_SIZE];
    if (RAND_bytes(iv, KEYSTORE_IV_SIZE) != 1 || RAND_bytes(salt, KEYSTORE_SALT_SIZE) != 1)
        return KEYSTORE_ERR_CRYPTO;
    
    uint8_t file_key[32];
    if (PKCS5_PBKDF2_HMAC((const char *)ctx->master_key, 32, salt, KEYSTORE_SALT_SIZE,
                          1000, EVP_sha256(), 32, file_key) != 1)
        return KEYSTORE_ERR_CRYPTO;
    
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { keystore_secure_wipe(file_key, sizeof(file_key)); return KEYSTORE_ERR_MEMORY; }
    
    uint8_t *ciphertext = malloc(key_size + EVP_MAX_BLOCK_LENGTH);
    uint8_t tag[KEYSTORE_TAG_SIZE];
    int len, ciphertext_len;
    
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        keystore_secure_wipe(file_key, sizeof(file_key));
        return KEYSTORE_ERR_MEMORY;
    }
    
    if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, file_key, iv) != 1 ||
        EVP_EncryptUpdate(cipher_ctx, NULL, &len, (uint8_t *)ctx->device_id, strlen(ctx->device_id)) != 1 ||
        EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, key_data, key_size) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        keystore_secure_wipe(file_key, sizeof(file_key));
        free(ciphertext);
        return KEYSTORE_ERR_CRYPTO;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, KEYSTORE_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        keystore_secure_wipe(file_key, sizeof(file_key));
        free(ciphertext);
        return KEYSTORE_ERR_CRYPTO;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(cipher_ctx);
    keystore_secure_wipe(file_key, sizeof(file_key));
    
    FILE *f = fopen(filepath, "wb");
    if (!f) { free(ciphertext); return KEYSTORE_ERR_FILE; }
    
    fwrite(KEYSTORE_MAGIC, 1, 4, f);
    fwrite(&KEYSTORE_VERSION, 1, 1, f);
    uint8_t type_byte = (uint8_t)key_type;
    fwrite(&type_byte, 1, 1, f);
    uint16_t size_be = ((key_size >> 8) & 0xFF) | ((key_size << 8) & 0xFF00);
    fwrite(&size_be, 2, 1, f);
    fwrite(salt, 1, KEYSTORE_SALT_SIZE, f);
    fwrite(iv, 1, KEYSTORE_IV_SIZE, f);
    fwrite(ciphertext, 1, ciphertext_len, f);
    fwrite(tag, 1, KEYSTORE_TAG_SIZE, f);
    fclose(f);
    chmod(filepath, 0600);
    free(ciphertext);
    
    printf("[keystore] Stored: %s\n", filepath);
    return KEYSTORE_OK;
}

int keystore_load_key(keystore_ctx_t *ctx, keystore_type_t key_type,
                      uint8_t *key_data, size_t *key_size) {
    if (!ctx || !ctx->initialized || !key_data || !key_size) return KEYSTORE_ERR_INVALID;
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", ctx->keystore_path, get_key_filename(key_type));
    
    FILE *f = fopen(filepath, "rb");
    if (!f) return KEYSTORE_ERR_FILE;
    
    uint8_t magic[4], version, type_byte;
    uint16_t stored_size;
    fread(magic, 1, 4, f);
    fread(&version, 1, 1, f);
    fread(&type_byte, 1, 1, f);
    fread(&stored_size, 2, 1, f);
    
    if (memcmp(magic, KEYSTORE_MAGIC, 4) != 0 || version != KEYSTORE_VERSION) {
        fclose(f);
        return KEYSTORE_ERR_INVALID;
    }
    
    size_t data_size = ((stored_size >> 8) & 0xFF) | ((stored_size << 8) & 0xFF00);
    if (data_size > *key_size) { fclose(f); return KEYSTORE_ERR_MEMORY; }
    
    uint8_t salt[KEYSTORE_SALT_SIZE], iv[KEYSTORE_IV_SIZE];
    fread(salt, 1, KEYSTORE_SALT_SIZE, f);
    fread(iv, 1, KEYSTORE_IV_SIZE, f);
    
    uint8_t *ciphertext = malloc(data_size + EVP_MAX_BLOCK_LENGTH + KEYSTORE_TAG_SIZE);
    if (!ciphertext) { fclose(f); return KEYSTORE_ERR_MEMORY; }
    
    size_t ciphertext_len = fread(ciphertext, 1, data_size + EVP_MAX_BLOCK_LENGTH + KEYSTORE_TAG_SIZE, f);
    fclose(f);
    
    if (ciphertext_len < KEYSTORE_TAG_SIZE) { free(ciphertext); return KEYSTORE_ERR_INVALID; }
    
    uint8_t tag[KEYSTORE_TAG_SIZE];
    ciphertext_len -= KEYSTORE_TAG_SIZE;
    memcpy(tag, ciphertext + ciphertext_len, KEYSTORE_TAG_SIZE);
    
    uint8_t file_key[32];
    if (PKCS5_PBKDF2_HMAC((const char *)ctx->master_key, 32, salt, KEYSTORE_SALT_SIZE,
                          1000, EVP_sha256(), 32, file_key) != 1) {
        free(ciphertext);
        return KEYSTORE_ERR_CRYPTO;
    }
    
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        keystore_secure_wipe(file_key, sizeof(file_key));
        free(ciphertext);
        return KEYSTORE_ERR_MEMORY;
    }
    
    int len, plaintext_len, ret = KEYSTORE_OK;
    
    if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, file_key, iv) != 1 ||
        EVP_DecryptUpdate(cipher_ctx, NULL, &len, (uint8_t *)ctx->device_id, strlen(ctx->device_id)) != 1 ||
        EVP_DecryptUpdate(cipher_ctx, key_data, &len, ciphertext, ciphertext_len) != 1) {
        ret = KEYSTORE_ERR_CRYPTO;
    } else {
        plaintext_len = len;
        if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, KEYSTORE_TAG_SIZE, tag) != 1 ||
            EVP_DecryptFinal_ex(cipher_ctx, key_data + len, &len) != 1) {
            fprintf(stderr, "[keystore] SECURITY ALERT: Tampering detected on %s\n", filepath);
            ret = KEYSTORE_ERR_AUTH;
        } else {
            plaintext_len += len;
            *key_size = plaintext_len;
            printf("[keystore] Loaded: %s\n", filepath);
        }
    }
    
    EVP_CIPHER_CTX_free(cipher_ctx);
    keystore_secure_wipe(file_key, sizeof(file_key));
    free(ciphertext);
    return ret;
}

int keystore_store_trusted_clients(keystore_ctx_t *ctx, const uint8_t *client_keys,
                                   size_t key_size, size_t num_clients) {
    if (!ctx || !ctx->initialized || !client_keys || num_clients == 0) return KEYSTORE_ERR_INVALID;
    
    size_t blob_size = 8 + (key_size * num_clients);
    uint8_t *blob = malloc(blob_size);
    if (!blob) return KEYSTORE_ERR_MEMORY;
    
    blob[0] = (num_clients >> 24) & 0xFF;
    blob[1] = (num_clients >> 16) & 0xFF;
    blob[2] = (num_clients >> 8) & 0xFF;
    blob[3] = num_clients & 0xFF;
    blob[4] = (key_size >> 24) & 0xFF;
    blob[5] = (key_size >> 16) & 0xFF;
    blob[6] = (key_size >> 8) & 0xFF;
    blob[7] = key_size & 0xFF;
    memcpy(blob + 8, client_keys, key_size * num_clients);
    
    int ret = keystore_store_key(ctx, KEYTYPE_TRUSTED_CLIENTS, blob, blob_size);
    keystore_secure_wipe(blob, blob_size);
    free(blob);
    return ret;
}

int keystore_load_trusted_clients(keystore_ctx_t *ctx, uint8_t *client_keys,
                                  size_t key_size, size_t max_clients, size_t *num_clients) {
    if (!ctx || !ctx->initialized || !client_keys || !num_clients) return KEYSTORE_ERR_INVALID;
    
    size_t blob_size = 8 + (key_size * max_clients);
    uint8_t *blob = malloc(blob_size);
    if (!blob) return KEYSTORE_ERR_MEMORY;
    
    int ret = keystore_load_key(ctx, KEYTYPE_TRUSTED_CLIENTS, blob, &blob_size);
    if (ret != KEYSTORE_OK) { free(blob); return ret; }
    
    size_t stored_count = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
    size_t stored_key_size = (blob[4] << 24) | (blob[5] << 16) | (blob[6] << 8) | blob[7];
    
    if (stored_key_size != key_size) { free(blob); return KEYSTORE_ERR_INVALID; }
    
    *num_clients = (stored_count < max_clients) ? stored_count : max_clients;
    memcpy(client_keys, blob + 8, key_size * (*num_clients));
    
    g_num_trusted_clients = *num_clients;
    for (size_t i = 0; i < *num_clients && i < MAX_TRUSTED_CLIENTS; i++)
        memcpy(g_trusted_client_keys[i], blob + 8 + (i * key_size), key_size);
    g_trusted_clients_loaded = true;
    
    free(blob);
    printf("[keystore] Loaded %zu trusted client(s)\n", *num_clients);
    return KEYSTORE_OK;
}

bool keystore_is_client_trusted(keystore_ctx_t *ctx, const uint8_t *client_pk, size_t key_size) {
    (void)ctx;
    if (!g_trusted_clients_loaded || !client_pk) return false;
    
    for (size_t i = 0; i < g_num_trusted_clients; i++) {
        volatile int diff = 0;
        for (size_t j = 0; j < key_size; j++)
            diff |= g_trusted_client_keys[i][j] ^ client_pk[j];
        if (diff == 0) return true;
    }
    return false;
}

void keystore_cleanup(keystore_ctx_t *ctx) {
    if (ctx) {
        keystore_secure_wipe(ctx->master_key, sizeof(ctx->master_key));
        keystore_secure_wipe(ctx, sizeof(keystore_ctx_t));
    }
    keystore_secure_wipe(g_trusted_client_keys, sizeof(g_trusted_client_keys));
    g_num_trusted_clients = 0;
    g_trusted_clients_loaded = false;
}
