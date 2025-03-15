#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Handshake states
typedef enum {
    STATE_CLIENT_HELLO,
    STATE_CLIENT_WAIT_SERVER_HELLO,
    STATE_ESTABLISHED
} client_state_t;

typedef enum {
    STATE_SERVER_WAIT_CLIENT_HELLO,
    STATE_SERVER_HELLO,
    STATE_SERVER_WAIT_FINISHED,
    STATE_SERVER_ESTABLISHED
} server_state_t;

// Global state variables
static client_state_t client_state = STATE_CLIENT_HELLO;
static server_state_t server_state = STATE_SERVER_WAIT_CLIENT_HELLO;

// Client handshake buffers
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t client_public_key[512];
static size_t client_public_key_len = 0;

// Server handshake buffers
static uint8_t server_nonce[NONCE_SIZE];
static uint8_t server_ephemeral_public_key[512];
static size_t server_ephemeral_public_key_len = 0;

// Cached handshake messages for transcript
static uint8_t client_hello_msg[1024];
static size_t client_hello_len = 0;
static uint8_t server_hello_msg[2048];
static size_t server_hello_len = 0;

// Buffer for received Client Hello on server side
static uint8_t received_client_hello[1024];
static size_t received_client_hello_len = 0;
static uint8_t server_handshake_buf[2048];
static size_t server_handshake_len = 0;

static int needs_key_derivation = 0;

void init_sec(int type, char* host) {
    UNUSED(host);
    init_io();

    if (type == CLIENT) {
        fprintf(stderr, "DEBUG (client): Starting init_sec\n");
        generate_private_key();
        derive_public_key();
        if (public_key && pub_key_size > 0) {
            client_public_key_len = pub_key_size;
            memcpy(client_public_key, public_key, client_public_key_len);
            fprintf(stderr, "DEBUG (client): Client ephemeral public key, length = %zu\n", client_public_key_len);
        } else {
            fprintf(stderr, "DEBUG (client): Failed to generate client ephemeral public key!\n");
        }
        generate_nonce(client_nonce, NONCE_SIZE);
        fprintf(stderr, "DEBUG (client): Client nonce, first 4 bytes: %02x %02x %02x %02x\n",
                client_nonce[0], client_nonce[1], client_nonce[2], client_nonce[3]);
        client_state = STATE_CLIENT_HELLO;
    } else if (type == SERVER) {
        fprintf(stderr, "DEBUG (server): Starting init_sec\n");
        server_state = STATE_SERVER_WAIT_CLIENT_HELLO;
        client_state = STATE_ESTABLISHED;  // Prevent server from taking the client branch
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        fprintf(stderr, "DEBUG (server): Loaded server certificate & private key\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (client_state == STATE_CLIENT_HELLO) {
        tlv* clientHello = create_tlv(CLIENT_HELLO);
        tlv* nonceTLV = create_tlv(NONCE);
        add_val(nonceTLV, client_nonce, NONCE_SIZE);
        add_tlv(clientHello, nonceTLV);

        fprintf(stderr, "DEBUG (client): Adding public key TLV with length = %zu\n", client_public_key_len);
        tlv* pubKeyTLV = create_tlv(PUBLIC_KEY);
        add_val(pubKeyTLV, client_public_key, client_public_key_len);
        add_tlv(clientHello, pubKeyTLV);

        uint16_t serialized_len = serialize_tlv(buf, clientHello);
        if (serialized_len <= sizeof(client_hello_msg)) {
            memcpy(client_hello_msg, buf, serialized_len);
            client_hello_len = serialized_len;
        } else {
            fprintf(stderr, "DEBUG (client): Client Hello too large to cache\n");
        }
        fprintf(stderr, "DEBUG (client): RIGHT BEFORE SENDING:\n");
        print_tlv_bytes(buf, serialized_len);
        free_tlv(clientHello);
        client_state = STATE_CLIENT_WAIT_SERVER_HELLO;
        return serialized_len;
    }
    else if (server_state == STATE_SERVER_HELLO) {
        tlv* serverHello = create_tlv(SERVER_HELLO);
        tlv* nonceTLV = create_tlv(NONCE);
        add_val(nonceTLV, server_nonce, NONCE_SIZE);
        add_tlv(serverHello, nonceTLV);

        tlv* certTLV = deserialize_tlv(certificate, cert_size);
        if (!certTLV) {
            fprintf(stderr, "DEBUG (server): Failed to deserialize certificate TLV\n");
            free_tlv(serverHello);
            return 0;
        }
        add_tlv(serverHello, certTLV);

        tlv* ephemeralPubTLV = create_tlv(PUBLIC_KEY);
        add_val(ephemeralPubTLV, server_ephemeral_public_key, server_ephemeral_public_key_len);
        add_tlv(serverHello, ephemeralPubTLV);

        uint8_t transcript[4096];
        size_t offset = 0;
        tlv* clientHelloTlv = deserialize_tlv(received_client_hello, received_client_hello_len);
        if (!clientHelloTlv) {
            fprintf(stderr, "DEBUG (server): Failed to deserialize cached Client Hello\n");
            free_tlv(serverHello);
            return 0;
        }
        offset += serialize_tlv(transcript + offset, clientHelloTlv);
        free_tlv(clientHelloTlv);
        offset += serialize_tlv(transcript + offset, nonceTLV);
        offset += serialize_tlv(transcript + offset, certTLV);
        offset += serialize_tlv(transcript + offset, ephemeralPubTLV);
        fprintf(stderr, "DEBUG (server): Handshake transcript length = %zu\n", offset);

        uint8_t handshake_sig[128];
        size_t handshake_sig_len = sign(handshake_sig, transcript, offset);
        fprintf(stderr, "DEBUG (server): Handshake signature length = %zu\n", handshake_sig_len);

        tlv* handshakeSigTLV = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(handshakeSigTLV, handshake_sig, handshake_sig_len);
        add_tlv(serverHello, handshakeSigTLV);

        uint16_t serialized_len = serialize_tlv(buf, serverHello);
        if (serialized_len <= sizeof(server_hello_msg)) {
            memcpy(server_hello_msg, buf, serialized_len);
            server_hello_len = serialized_len;
        } else {
            fprintf(stderr, "DEBUG (server): Server Hello too large to cache\n");
        }
        fprintf(stderr, "DEBUG (server): Serialized Server Hello:\n");
        print_tlv_bytes(buf, serialized_len);

        free_tlv(serverHello);
        server_state = STATE_SERVER_WAIT_FINISHED;
        needs_key_derivation = 1;
        return serialized_len;
    }
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    if (server_state == STATE_SERVER_WAIT_CLIENT_HELLO) {
        if (server_handshake_len + length > sizeof(server_handshake_buf)) {
            fprintf(stderr, "DEBUG (server): Handshake buffer overflow!\n");
            return;
        }
        memcpy(server_handshake_buf + server_handshake_len, buf, length);
        server_handshake_len += length;
    
        tlv* received_tlv = deserialize_tlv(server_handshake_buf, server_handshake_len);
        if (!received_tlv) {
            fprintf(stderr, "DEBUG (server): Incomplete Client Hello, waiting for more data\n");
            return;
        }
    
        uint8_t temp_buf[4096];
        uint16_t complete_len = serialize_tlv(temp_buf, received_tlv);
        if (complete_len != server_handshake_len) {
            fprintf(stderr, "DEBUG (server): Incomplete packet: expected %u, got %zu. Waiting for more data.\n",
                    complete_len, server_handshake_len);
            free_tlv(received_tlv);
            return;
        }
    
        if (received_tlv->type == CLIENT_HELLO) {
            memcpy(received_client_hello, server_handshake_buf, server_handshake_len);
            received_client_hello_len = server_handshake_len;
            server_handshake_len = 0;
    
            tlv* clientNonceTLV = get_tlv(received_tlv, NONCE);
            tlv* clientPubKeyTLV = get_tlv(received_tlv, PUBLIC_KEY);
            if (clientNonceTLV && clientPubKeyTLV) {
                load_peer_public_key(clientPubKeyTLV->val, clientPubKeyTLV->length);
            } else {
                fprintf(stderr, "DEBUG (server): Missing TLV fields in Client Hello\n");
            }
    
            generate_nonce(server_nonce, NONCE_SIZE);
            generate_private_key();
            derive_public_key();
            if (public_key && pub_key_size > 0) {
                server_ephemeral_public_key_len = pub_key_size;
                memcpy(server_ephemeral_public_key, public_key, server_ephemeral_public_key_len);
                fprintf(stderr, "DEBUG (server): Generated server ephemeral public key, length = %zu\n", server_ephemeral_public_key_len);
            } else {
                fprintf(stderr, "DEBUG (server): Failed to generate server ephemeral public key!\n");
            }
            server_state = STATE_SERVER_HELLO;
            free_tlv(received_tlv);
            return;
        } else {
            fprintf(stderr, "DEBUG (server): Unexpected TLV type %02x\n", received_tlv->type);
            free_tlv(received_tlv);
            return;
        }
    }    
    
    if (client_state == STATE_CLIENT_WAIT_SERVER_HELLO) {
        if (length <= sizeof(server_hello_msg)) {
            memcpy(server_hello_msg, buf, length);
            server_hello_len = length;
        } else {
            fprintf(stderr, "DEBUG (client): Server Hello too large to cache\n");
        }
        derive_secret();
        uint8_t* salt = malloc(client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (client): Salt allocation failed\n");
            return;
        }
        memcpy(salt, client_hello_msg, client_hello_len);
        memcpy(salt + client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, client_hello_len + server_hello_len);
        free(salt);
        client_state = STATE_ESTABLISHED;
        output_io(buf, length);
        return;
    }
    
    if (needs_key_derivation) {
        derive_secret();
        uint8_t* salt = malloc(received_client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (server): Salt allocation failed\n");
            return;
        }
        memcpy(salt, received_client_hello, received_client_hello_len);
        memcpy(salt + received_client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, received_client_hello_len + server_hello_len);
        free(salt);
        needs_key_derivation = 0;
    }
    
    output_io(buf, length);
}
