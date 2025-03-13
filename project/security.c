#include "consts.h"
#include "io.h"
#include "libsecurity.h"  // Provides generate_private_key(), derive_public_key(), etc.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Define client handshake states.
typedef enum {
    STATE_CLIENT_HELLO,
    STATE_CLIENT_WAIT_SERVER_HELLO,
    STATE_ESTABLISHED
} client_state_t;

static client_state_t client_state = STATE_CLIENT_HELLO;

// Global buffers for nonce and ephemeral public key.
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t client_public_key[512];  // Adjust size if necessary.
static size_t client_public_key_len = 0;

// Optionally, store the serialized Client Hello for later use.
static uint8_t client_hello_msg[1024];
static size_t client_hello_len = 0;

void init_sec(int type, char* host) {
    UNUSED(host);
    init_io();

    if (type == CLIENT) {
        // Generate the client nonce.
        generate_nonce(client_nonce, NONCE_SIZE);

        // Generate the ephemeral key pair.
        generate_private_key();

        // Derive the public key; libsecurity will set the global variables
        // 'public_key' and 'pub_key_size' accordingly.
        derive_public_key();

        // Copy the derived public key from libsecurity's global variables.
        if (public_key != NULL && pub_key_size > 0) {
            client_public_key_len = pub_key_size;
            memcpy(client_public_key, public_key, client_public_key_len);
        }
        
        // Set the initial state to send the Client Hello.
        client_state = STATE_CLIENT_HELLO;
    }
}

// input_sec() is called by libtransport when data is to be sent.
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // When in the handshake phase, send the Client Hello.
    if (client_state == STATE_CLIENT_HELLO) {
        // Create the Client Hello TLV.
        tlv* clientHello = create_tlv(CLIENT_HELLO);

        // Create and add the NONCE TLV.
        tlv* nonceTLV = create_tlv(NONCE);
        add_val(nonceTLV, client_nonce, NONCE_SIZE);
        add_tlv(clientHello, nonceTLV);

        // Create and add the PUBLIC_KEY TLV.
        tlv* pubKeyTLV = create_tlv(PUBLIC_KEY);
        add_val(pubKeyTLV, client_public_key, client_public_key_len);
        add_tlv(clientHello, pubKeyTLV);

        // Serialize the TLV into the output buffer.
        uint16_t serialized_len = serialize_tlv(buf, clientHello);

        // Optionally, store the serialized Client Hello for transcript use later.
        if (serialized_len <= sizeof(client_hello_msg)) {
            memcpy(client_hello_msg, buf, serialized_len);
            client_hello_len = serialized_len;
        }

        // Free the allocated TLV tree.
        free_tlv(clientHello);

        // Transition to waiting for the Server Hello.
        client_state = STATE_CLIENT_WAIT_SERVER_HELLO;

        return serialized_len;
    } else {
        // For non-handshake data, simply pass through to IO.
        return input_io(buf, max_length);
    }
}

// output_sec() is called when data is received from the network.
void output_sec(uint8_t* buf, size_t length) {
    // For now, simply forward the received data to the underlying IO layer.
    output_io(buf, length);
}
