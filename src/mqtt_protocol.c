/*
 * mqtt_protocol.c - MQTT Protocol Implementation
 */

#include "mqtt_protocol.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// Utility Functions
// ============================================================================

static int write_string(uint8_t **buf, const char *str) {
    if (!str) return 0;
    
    size_t len = strlen(str);
    (*buf)[0] = (len >> 8) & 0xFF;
    (*buf)[1] = len & 0xFF;
    memcpy(*buf + 2, str, len);
    *buf += 2 + len;
    
    return 2 + len;
}

int mqtt_encode_remaining_length(uint32_t length, uint8_t *buffer) {
    int bytes = 0;
    
    do {
        uint8_t digit = length % 128;
        length /= 128;
        if (length > 0) {
            digit |= 0x80;
        }
        buffer[bytes++] = digit;
    } while (length > 0 && bytes < 4);
    
    return bytes;
}

int mqtt_decode_remaining_length(const uint8_t *buffer, size_t len,
                                uint32_t *remaining_length, int *bytes_used) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    int pos = 0;
    uint8_t digit;
    
    do {
        if (pos >= (int)len) return MQTT_ERR_INVALID;
        
        digit = buffer[pos++];
        value += (digit & 0x7F) * multiplier;
        multiplier *= 128;
        
        if (multiplier > 128 * 128 * 128) {
            return MQTT_ERR_PROTOCOL;
        }
    } while ((digit & 0x80) != 0);
    
    *remaining_length = value;
    *bytes_used = pos;
    return MQTT_OK;
}

// ============================================================================
// CONNECT Packet
// ============================================================================

int mqtt_build_connect(const mqtt_connect_t *connect,
                      uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len) {
    uint8_t *ptr = buffer;
    uint8_t *remaining_len_ptr;
    
    // Fixed header
    *ptr++ = MQTT_CONNECT;
    remaining_len_ptr = ptr;  // We'll fill this in later
    ptr += 4;  // Reserve max space for remaining length
    
    // Variable header
    // Protocol name: "MQTT"
    *ptr++ = 0x00;
    *ptr++ = 0x04;
    memcpy(ptr, "MQTT", 4);
    ptr += 4;
    
    // Protocol level: 4 (MQTT 3.1.1)
    *ptr++ = 0x04;
    
    // Connect flags
    uint8_t flags = 0;
    if (connect->clean_session) flags |= 0x02;
    if (connect->will_topic) {
        flags |= 0x04;  // Will flag
        flags |= (connect->will_qos & 0x03) << 3;  // Will QoS
        if (connect->will_retain) flags |= 0x20;
    }
    if (connect->username) flags |= 0x80;
    if (connect->password) flags |= 0x40;
    *ptr++ = flags;
    
    // Keep alive
    *ptr++ = (connect->keepalive >> 8) & 0xFF;
    *ptr++ = connect->keepalive & 0xFF;
    
    // Payload
    // Client ID (required)
    write_string(&ptr, connect->client_id);
    
    // Will topic and message
    if (connect->will_topic) {
        write_string(&ptr, connect->will_topic);
        
        uint16_t will_len = connect->will_payload_len;
        *ptr++ = (will_len >> 8) & 0xFF;
        *ptr++ = will_len & 0xFF;
        if (will_len > 0) {
            memcpy(ptr, connect->will_payload, will_len);
            ptr += will_len;
        }
    }
    
    // Username
    if (connect->username) {
        write_string(&ptr, connect->username);
    }
    
    // Password
    if (connect->password) {
        write_string(&ptr, connect->password);
    }
    
    // Calculate remaining length
    size_t remaining = ptr - (remaining_len_ptr + 4);
    int rl_bytes = mqtt_encode_remaining_length(remaining, remaining_len_ptr);
    
    // Move data if we used fewer bytes for remaining length
    if (rl_bytes < 4) {
        memmove(remaining_len_ptr + rl_bytes, remaining_len_ptr + 4, remaining);
        ptr -= (4 - rl_bytes);
    }
    
    *packet_len = ptr - buffer;
    
    return (*packet_len <= buffer_size) ? MQTT_OK : MQTT_ERR_BUFFER_FULL;
}

// ============================================================================
// CONNACK Packet
// ============================================================================

int mqtt_parse_connack(const uint8_t *buffer, size_t len,
                      mqtt_connack_t *connack) {
    if (len < 4) return MQTT_ERR_INVALID;
    if (buffer[0] != MQTT_CONNACK) return MQTT_ERR_PROTOCOL;
    
    // Skip fixed header and remaining length
    connack->session_present = buffer[2] & 0x01;
    connack->return_code = buffer[3];
    
    return MQTT_OK;
}

// ============================================================================
// PUBLISH Packet
// ============================================================================

int mqtt_build_publish(const mqtt_publish_t *publish,
                      uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len) {
    uint8_t *ptr = buffer;
    
    // Fixed header
    uint8_t fixed_header = MQTT_PUBLISH;
    if (publish->dup) fixed_header |= 0x08;
    fixed_header |= (publish->qos & 0x03) << 1;
    if (publish->retain) fixed_header |= 0x01;
    
    *ptr++ = fixed_header;
    
    // Calculate remaining length
    size_t topic_len = strlen(publish->topic);
    size_t remaining = 2 + topic_len + publish->payload_len;
    
    if (publish->qos > 0) {
        remaining += 2;  // Packet ID
    }
    
    int rl_bytes = mqtt_encode_remaining_length(remaining, ptr);
    ptr += rl_bytes;
    
    // Topic
    *ptr++ = (topic_len >> 8) & 0xFF;
    *ptr++ = topic_len & 0xFF;
    memcpy(ptr, publish->topic, topic_len);
    ptr += topic_len;
    
    // Packet ID (only for QoS 1 and 2)
    if (publish->qos > 0) {
        *ptr++ = (publish->packet_id >> 8) & 0xFF;
        *ptr++ = publish->packet_id & 0xFF;
    }
    
    // Payload
    if (publish->payload_len > 0) {
        memcpy(ptr, publish->payload, publish->payload_len);
        ptr += publish->payload_len;
    }
    
    *packet_len = ptr - buffer;
    
    return (*packet_len <= buffer_size) ? MQTT_OK : MQTT_ERR_BUFFER_FULL;
}

// ============================================================================
// PUBLISH Parse
// ============================================================================

int mqtt_parse_publish(const uint8_t *buffer, size_t len,
                      mqtt_publish_t *publish) {
    if (len < 2) return MQTT_ERR_INVALID;
    
    uint8_t fixed_header = buffer[0];
    if ((fixed_header & 0xF0) != MQTT_PUBLISH) return MQTT_ERR_PROTOCOL;
    
    publish->dup = (fixed_header & 0x08) != 0;
    publish->qos = (fixed_header >> 1) & 0x03;
    publish->retain = (fixed_header & 0x01) != 0;
    
    // Decode remaining length
    uint32_t remaining_length;
    int rl_bytes;
    int ret = mqtt_decode_remaining_length(buffer + 1, len - 1,
                                          &remaining_length, &rl_bytes);
    if (ret != MQTT_OK) return ret;
    
    const uint8_t *ptr = buffer + 1 + rl_bytes;
    
    // Topic length
    uint16_t topic_len = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    
    // Topic (we can't allocate, so just point to it)
    publish->topic = (const char *)ptr;
    ptr += topic_len;
    
    // Packet ID (only for QoS 1 and 2)
    if (publish->qos > 0) {
        publish->packet_id = (ptr[0] << 8) | ptr[1];
        ptr += 2;
    } else {
        publish->packet_id = 0;
    }
    
    // Payload
    size_t header_len = ptr - buffer;
    publish->payload = ptr;
    publish->payload_len = len - header_len;
    
    return MQTT_OK;
}

// ============================================================================
// DISCONNECT Packet
// ============================================================================

int mqtt_build_disconnect(uint8_t *buffer, size_t buffer_size,
                         size_t *packet_len) {
    if (buffer_size < 2) return MQTT_ERR_BUFFER_FULL;
    
    buffer[0] = MQTT_DISCONNECT;
    buffer[1] = 0x00;  // Remaining length = 0
    
    *packet_len = 2;
    return MQTT_OK;
}

// ============================================================================
// PINGREQ Packet
// ============================================================================

int mqtt_build_pingreq(uint8_t *buffer, size_t buffer_size,
                      size_t *packet_len) {
    if (buffer_size < 2) return MQTT_ERR_BUFFER_FULL;
    
    buffer[0] = MQTT_PINGREQ;
    buffer[1] = 0x00;  // Remaining length = 0
    
    *packet_len = 2;
    return MQTT_OK;
}

// ============================================================================
// Error Handling
// ============================================================================

const char* mqtt_strerror(int err) {
    switch (err) {
        case MQTT_OK: return "Success";
        case MQTT_ERR_BUFFER_FULL: return "Buffer full";
        case MQTT_ERR_INVALID: return "Invalid packet";
        case MQTT_ERR_PROTOCOL: return "Protocol error";
        default: return "Unknown error";
    }
}
