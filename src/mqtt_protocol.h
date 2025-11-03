/*
 * mqtt_protocol.h - MQTT Protocol Handler
 * 
 * Implements MQTT 3.1.1 packet construction and parsing
 */

#ifndef MQTT_PROTOCOL_H
#define MQTT_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================================================
// MQTT Control Packet Types
// ============================================================================

#define MQTT_CONNECT        0x10
#define MQTT_CONNACK        0x20
#define MQTT_PUBLISH        0x30
#define MQTT_PUBACK         0x40
#define MQTT_PUBREC         0x50
#define MQTT_PUBREL         0x60
#define MQTT_PUBCOMP        0x70
#define MQTT_SUBSCRIBE      0x80
#define MQTT_SUBACK         0x90
#define MQTT_UNSUBSCRIBE    0xA0
#define MQTT_UNSUBACK       0xB0
#define MQTT_PINGREQ        0xC0
#define MQTT_PINGRESP       0xD0
#define MQTT_DISCONNECT     0xE0

// QoS Levels
#define MQTT_QOS_0          0x00  // At most once
#define MQTT_QOS_1          0x01  // At least once
#define MQTT_QOS_2          0x02  // Exactly once

// ============================================================================
// MQTT Packet Structures
// ============================================================================

typedef struct {
    const char *client_id;
    const char *username;
    const char *password;
    const char *will_topic;
    const uint8_t *will_payload;
    size_t will_payload_len;
    uint8_t will_qos;
    bool will_retain;
    uint16_t keepalive;
    bool clean_session;
} mqtt_connect_t;

typedef struct {
    uint8_t session_present;
    uint8_t return_code;
} mqtt_connack_t;

typedef struct {
    const char *topic;
    const uint8_t *payload;
    size_t payload_len;
    uint8_t qos;
    bool retain;
    bool dup;
    uint16_t packet_id;  // Only for QoS 1 and 2
} mqtt_publish_t;

// ============================================================================
// API Functions
// ============================================================================

// Build CONNECT packet
int mqtt_build_connect(const mqtt_connect_t *connect,
                      uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len);

// Parse CONNACK packet
int mqtt_parse_connack(const uint8_t *buffer, size_t len,
                      mqtt_connack_t *connack);

// Build PUBLISH packet
int mqtt_build_publish(const mqtt_publish_t *publish,
                      uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len);

// Parse PUBLISH packet
int mqtt_parse_publish(const uint8_t *buffer, size_t len,
                      mqtt_publish_t *publish);

// Build SUBSCRIBE packet
int mqtt_build_subscribe(const char **topics, uint8_t *qos_levels,
                        size_t topic_count, uint16_t packet_id,
                        uint8_t *buffer, size_t buffer_size,
                        size_t *packet_len);

// Build DISCONNECT packet
int mqtt_build_disconnect(uint8_t *buffer, size_t buffer_size,
                         size_t *packet_len);

// Build PINGREQ packet
int mqtt_build_pingreq(uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len);

// Utility: Encode remaining length
int mqtt_encode_remaining_length(uint32_t length, uint8_t *buffer);

// Utility: Decode remaining length
int mqtt_decode_remaining_length(const uint8_t *buffer, size_t len,
                                uint32_t *remaining_length, int *bytes_used);

// Error codes
#define MQTT_OK              0
#define MQTT_ERR_BUFFER_FULL -1
#define MQTT_ERR_INVALID     -2
#define MQTT_ERR_PROTOCOL    -3

const char* mqtt_strerror(int err);

#endif // MQTT_PROTOCOL_H
