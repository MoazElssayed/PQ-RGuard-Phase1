/*
 * pqrguard_provision.c - Key Provisioning Tool for PQ-RGuard
 * 
 * Compile:
 *   gcc -o pqrguard_provision pqrguard_provision.c secure_keystore.c \
 *       -I. -lssl -lcrypto -loqs
 */

#include "secure_keystore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <oqs/oqs.h>

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

static int read_password_confirm(char *password, size_t max_len) {
    char confirm[256];
    
    if (read_password("Enter new keystore password: ", password, max_len) != 0) return -1;
    if (strlen(password) < 8) {
        fprintf(stderr, "Error: Password must be at least 8 characters\n");
        return -1;
    }
    if (read_password("Confirm password: ", confirm, sizeof(confirm)) != 0) {
        keystore_secure_wipe(password, max_len);
        return -1;
    }
    if (strcmp(password, confirm) != 0) {
        fprintf(stderr, "Error: Passwords do not match\n");
        keystore_secure_wipe(password, max_len);
        keystore_secure_wipe(confirm, sizeof(confirm));
        return -1;
    }
    keystore_secure_wipe(confirm, sizeof(confirm));
    return 0;
}

static int init_broker(const char *keystore_path, const char *device_id) {
    keystore_ctx_t keystore;
    char password[256];
    
    printf("=== BROKER INITIALIZATION ===\n\n");
    mkdir(keystore_path, 0700);
    
    if (read_password_confirm(password, sizeof(password)) != 0) return -1;
    if (keystore_init(&keystore, device_id, keystore_path, password) != KEYSTORE_OK) {
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    printf("\nGenerating ML-KEM-512 keypair...\n");
    
    uint8_t broker_pk[KYBER512_PK_BYTES], broker_sk[KYBER512_SK_BYTES];
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem || OQS_KEM_keypair(kem, broker_pk, broker_sk) != OQS_SUCCESS) {
        if (kem) OQS_KEM_free(kem);
        keystore_cleanup(&keystore);
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    OQS_KEM_free(kem);
    
    if (keystore_store_key(&keystore, KEYTYPE_BROKER_PUBLIC, broker_pk, sizeof(broker_pk)) != KEYSTORE_OK ||
        keystore_store_key(&keystore, KEYTYPE_BROKER_SECRET, broker_sk, sizeof(broker_sk)) != KEYSTORE_OK) {
        keystore_secure_wipe(broker_pk, sizeof(broker_pk));
        keystore_secure_wipe(broker_sk, sizeof(broker_sk));
        keystore_cleanup(&keystore);
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    char export_path[512];
    snprintf(export_path, sizeof(export_path), "%s/broker_public_key.bin", keystore_path);
    FILE *f = fopen(export_path, "wb");
    if (f) { fwrite(broker_pk, 1, sizeof(broker_pk), f); fclose(f); }
    
    printf("\n=== BROKER INITIALIZED ===\n");
    printf("Keystore:   %s\n", keystore_path);
    printf("Device ID:  %s\n", device_id);
    printf("Algorithm:  ML-KEM-512 (Kyber)\n");
    printf("Encryption: AES-256-GCM + PBKDF2 (100k iter)\n");
    printf("Exported:   broker_public_key.bin\n");
    printf("\nWARNING: Distribute to clients via SECURE CHANNEL only!\n");
    
    keystore_secure_wipe(broker_pk, sizeof(broker_pk));
    keystore_secure_wipe(broker_sk, sizeof(broker_sk));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&keystore);
    return 0;
}

static int init_client(const char *keystore_path, const char *device_id, const char *broker_key_file) {
    keystore_ctx_t keystore;
    char password[256];
    
    printf("=== CLIENT INITIALIZATION ===\n\n");
    
    if (!broker_key_file) {
        fprintf(stderr, "Error: Must provide broker public key file\n");
        fprintf(stderr, "Usage: --init-client --import-broker <broker_public_key.bin>\n");
        return -1;
    }
    
    FILE *f = fopen(broker_key_file, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open %s\n", broker_key_file); return -1; }
    
    uint8_t broker_pk[KYBER512_PK_BYTES];
    if (fread(broker_pk, 1, sizeof(broker_pk), f) != sizeof(broker_pk)) {
        fclose(f);
        fprintf(stderr, "Error: Invalid broker key file\n");
        return -1;
    }
    fclose(f);
    printf("Read broker public key from: %s\n\n", broker_key_file);
    
    mkdir(keystore_path, 0700);
    if (read_password_confirm(password, sizeof(password)) != 0) return -1;
    if (keystore_init(&keystore, device_id, keystore_path, password) != KEYSTORE_OK) {
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    if (keystore_store_key(&keystore, KEYTYPE_TRUSTED_BROKER, broker_pk, sizeof(broker_pk)) != KEYSTORE_OK) {
        keystore_cleanup(&keystore);
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    printf("Generating ML-KEM-512 keypair...\n");
    uint8_t client_pk[KYBER512_PK_BYTES], client_sk[KYBER512_SK_BYTES];
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem || OQS_KEM_keypair(kem, client_pk, client_sk) != OQS_SUCCESS) {
        if (kem) OQS_KEM_free(kem);
        keystore_cleanup(&keystore);
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    OQS_KEM_free(kem);
    
    if (keystore_store_key(&keystore, KEYTYPE_CLIENT_PUBLIC, client_pk, sizeof(client_pk)) != KEYSTORE_OK ||
        keystore_store_key(&keystore, KEYTYPE_CLIENT_SECRET, client_sk, sizeof(client_sk)) != KEYSTORE_OK) {
        keystore_secure_wipe(client_pk, sizeof(client_pk));
        keystore_secure_wipe(client_sk, sizeof(client_sk));
        keystore_cleanup(&keystore);
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    char export_path[512];
    snprintf(export_path, sizeof(export_path), "%s/client_public_key.bin", keystore_path);
    f = fopen(export_path, "wb");
    if (f) { fwrite(client_pk, 1, sizeof(client_pk), f); fclose(f); }
    
    printf("\n=== CLIENT INITIALIZED ===\n");
    printf("Keystore:   %s\n", keystore_path);
    printf("Device ID:  %s\n", device_id);
    printf("Trusted:    Broker public key imported\n");
    printf("Exported:   client_public_key.bin\n");
    printf("\nWARNING: Send to broker admin via SECURE CHANNEL!\n");
    
    keystore_secure_wipe(broker_pk, sizeof(broker_pk));
    keystore_secure_wipe(client_pk, sizeof(client_pk));
    keystore_secure_wipe(client_sk, sizeof(client_sk));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&keystore);
    return 0;
}

static int add_trusted_client(const char *keystore_path, const char *client_key_file) {
    keystore_ctx_t keystore;
    char password[256];
    
    printf("=== ADD TRUSTED CLIENT ===\n\n");
    
    FILE *f = fopen(client_key_file, "rb");
    if (!f) { fprintf(stderr, "Error: Cannot open %s\n", client_key_file); return -1; }
    
    uint8_t new_client_pk[KYBER512_PK_BYTES];
    if (fread(new_client_pk, 1, sizeof(new_client_pk), f) != sizeof(new_client_pk)) {
        fclose(f);
        fprintf(stderr, "Error: Invalid client key file\n");
        return -1;
    }
    fclose(f);
    printf("Read client key from: %s\n\n", client_key_file);
    
    if (read_password("Enter keystore password: ", password, sizeof(password)) != 0) return -1;
    if (keystore_init(&keystore, "PQRGUARD_BROKER", keystore_path, password) != KEYSTORE_OK) {
        keystore_secure_wipe(password, sizeof(password));
        fprintf(stderr, "Failed to open keystore (wrong password?)\n");
        return -1;
    }
    
    uint8_t existing_clients[MAX_TRUSTED_CLIENTS * KYBER512_PK_BYTES];
    size_t num_existing = 0;
    keystore_load_trusted_clients(&keystore, existing_clients, KYBER512_PK_BYTES, MAX_TRUSTED_CLIENTS, &num_existing);
    
    for (size_t i = 0; i < num_existing; i++) {
        if (memcmp(existing_clients + (i * KYBER512_PK_BYTES), new_client_pk, KYBER512_PK_BYTES) == 0) {
            printf("Client already in trusted list\n");
            keystore_secure_wipe(password, sizeof(password));
            keystore_cleanup(&keystore);
            return 0;
        }
    }
    
    if (num_existing >= MAX_TRUSTED_CLIENTS) {
        fprintf(stderr, "Error: Maximum clients reached (%d)\n", MAX_TRUSTED_CLIENTS);
        keystore_secure_wipe(password, sizeof(password));
        keystore_cleanup(&keystore);
        return -1;
    }
    
    memcpy(existing_clients + (num_existing * KYBER512_PK_BYTES), new_client_pk, KYBER512_PK_BYTES);
    num_existing++;
    
    if (keystore_store_trusted_clients(&keystore, existing_clients, KYBER512_PK_BYTES, num_existing) != KEYSTORE_OK) {
        keystore_secure_wipe(existing_clients, sizeof(existing_clients));
        keystore_secure_wipe(password, sizeof(password));
        keystore_cleanup(&keystore);
        return -1;
    }
    
    printf("\n=== CLIENT AUTHORIZED ===\n");
    printf("Total trusted clients: %zu\n", num_existing);
    printf("Client can now connect to this broker\n");
    
    keystore_secure_wipe(existing_clients, sizeof(existing_clients));
    keystore_secure_wipe(new_client_pk, sizeof(new_client_pk));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&keystore);
    return 0;
}

static int list_trusted_clients(const char *keystore_path) {
    keystore_ctx_t keystore;
    char password[256];
    
    if (read_password("Enter keystore password: ", password, sizeof(password)) != 0) return -1;
    if (keystore_init(&keystore, "PQRGUARD_BROKER", keystore_path, password) != KEYSTORE_OK) {
        keystore_secure_wipe(password, sizeof(password));
        return -1;
    }
    
    uint8_t clients[MAX_TRUSTED_CLIENTS * KYBER512_PK_BYTES];
    size_t num_clients = 0;
    keystore_load_trusted_clients(&keystore, clients, KYBER512_PK_BYTES, MAX_TRUSTED_CLIENTS, &num_clients);
    
    printf("\nTrusted clients: %zu\n\n", num_clients);
    for (size_t i = 0; i < num_clients; i++) {
        printf("  [%zu] ", i + 1);
        for (int j = 0; j < 8; j++) printf("%02x", clients[i * KYBER512_PK_BYTES + j]);
        printf("...\n");
    }
    
    keystore_secure_wipe(clients, sizeof(clients));
    keystore_secure_wipe(password, sizeof(password));
    keystore_cleanup(&keystore);
    return 0;
}

static void print_usage(const char *prog) {
    printf("PQ-RGuard Key Provisioning Tool\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  --init-broker                  Initialize broker keystore\n");
    printf("  --init-client                  Initialize client keystore\n");
    printf("  --add-client <key.bin>         Add client to trusted list\n");
    printf("  --list-clients                 List trusted clients\n");
    printf("\nOptions:\n");
    printf("  -k <path>                      Keystore path (default: ./keystore)\n");
    printf("  -d <id>                        Device identifier\n");
    printf("  --import-broker <key.bin>      Import broker public key (for clients)\n");
    printf("\nExamples:\n\n");
    printf("  # On BROKER:\n");
    printf("  %s --init-broker -k /home/pi/keystore\n\n", prog);
    printf("  # On CLIENT (after receiving broker_public_key.bin):\n");
    printf("  %s --init-client --import-broker broker_public_key.bin\n\n", prog);
    printf("  # On BROKER (after receiving client_public_key.bin):\n");
    printf("  %s --add-client client_public_key.bin -k /home/pi/keystore\n", prog);
}

int main(int argc, char *argv[]) {
    const char *keystore_path = "./keystore", *device_id = NULL;
    const char *broker_key_file = NULL, *client_key_file = NULL;
    enum { CMD_NONE, CMD_INIT_BROKER, CMD_INIT_CLIENT, CMD_ADD_CLIENT, CMD_LIST } cmd = CMD_NONE;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--init-broker") == 0) cmd = CMD_INIT_BROKER;
        else if (strcmp(argv[i], "--init-client") == 0) cmd = CMD_INIT_CLIENT;
        else if (strcmp(argv[i], "--add-client") == 0 && i + 1 < argc) { cmd = CMD_ADD_CLIENT; client_key_file = argv[++i]; }
        else if (strcmp(argv[i], "--list-clients") == 0) cmd = CMD_LIST;
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) keystore_path = argv[++i];
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) device_id = argv[++i];
        else if (strcmp(argv[i], "--import-broker") == 0 && i + 1 < argc) broker_key_file = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { print_usage(argv[0]); return 0; }
    }
    
    switch (cmd) {
        case CMD_INIT_BROKER: return init_broker(keystore_path, device_id ? device_id : "PQRGUARD_BROKER");
        case CMD_INIT_CLIENT: return init_client(keystore_path, device_id ? device_id : "PQRGUARD_CLIENT", broker_key_file);
        case CMD_ADD_CLIENT:  return add_trusted_client(keystore_path, client_key_file);
        case CMD_LIST:        return list_trusted_clients(keystore_path);
        default:              print_usage(argv[0]); return 1;
    }
}
