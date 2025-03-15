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

// Define server handshake states
typedef enum {
    STATE_SERVER_WAIT_CLIENT_HELLO,
    STATE_SERVER_HELLO,
    STATE_SERVER_WAIT_FINISHED,
    STATE_SERVER_ESTABLISHED
} server_state_t;

static client_state_t client_state = STATE_CLIENT_HELLO;
static server_state_t server_state = STATE_SERVER_WAIT_CLIENT_HELLO;

// Global buffers for nonce and ephemeral public key.
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t client_public_key[512];  // Adjust size if necessary.
static size_t client_public_key_len = 0;

// Server globals
static uint8_t server_nonce[NONCE_SIZE];
static uint8_t server_ephemeral_public_key[512];
static size_t server_ephemeral_public_key_len = 0;

// Buffer to store received client hello message
static uint8_t received_client_hello[1024];
static size_t received_client_hello_len = 0;

// Buffer to store generated server hello message
static uint8_t server_hello_msg[2048]; // More space for certificate
static size_t server_hello_len = 0;

// Flag to indicate if we need to derive keys
static int needs_key_derivation = 0;

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
    } else if (type == SERVER) {
        // Initialize server in waiting state
        server_state = STATE_SERVER_WAIT_CLIENT_HELLO;
        
        // Load server certificate
        load_certificate("server_cert.bin");
        
        // Load server private key
        load_private_key("server_key.bin");
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

        // Debug output: print the Server Hello TLV structure.
        fprintf(stderr, "Client Hello TLV structure:\n");
        print_tlv_bytes(buf, serialized_len);

        // Free the allocated TLV tree.
        free_tlv(clientHello);

        // Transition to waiting for the Server Hello.
        client_state = STATE_CLIENT_WAIT_SERVER_HELLO;

        return serialized_len;
    } else if (server_state == STATE_SERVER_HELLO) {
        // Create the Server Hello message
        tlv* serverHello = create_tlv(SERVER_HELLO);
        
        // Add server nonce
        tlv* nonceTLV = create_tlv(NONCE);
        add_val(nonceTLV, server_nonce, NONCE_SIZE);
        add_tlv(serverHello, nonceTLV);
        
        // Add certificate directly from the loaded file
        // The certificate should already include DNS_NAME, PUBLIC_KEY, and SIGNATURE
        //fprintf(stderr, "Certificate: ");
        //print_tlv_bytes(certificate, cert_size);
        tlv* certTLV = create_tlv(CERTIFICATE);
        add_val(certTLV, certificate, cert_size);

        if (!certTLV) {
            fprintf(stderr, "Failed to deserialize certificate\n");
            free_tlv(serverHello);
            return 0;
        }
        add_tlv(serverHello, certTLV);
        
        // Add the ephemeral public key as a separate TLV after the certificate
        tlv* pubKeyTLV = create_tlv(PUBLIC_KEY);
        add_val(pubKeyTLV, public_key, pub_key_size);
        add_tlv(serverHello, pubKeyTLV);
        
        // Prepare data for the handshake signature
        size_t data_size = received_client_hello_len + NONCE_SIZE + cert_size + pub_key_size;
        uint8_t* data_to_sign = malloc(data_size);
        // size_t offset = 0;
        // memcpy(data_to_sign + offset, received_client_hello, received_client_hello_len);
        // offset += received_client_hello_len;
        // memcpy(data_to_sign + offset, server_nonce, NONCE_SIZE);
        // offset += NONCE_SIZE;
        // memcpy(data_to_sign + offset, certificate, cert_size);
        // offset += cert_size;
        // memcpy(data_to_sign + offset, server_ephemeral_public_key, pub_key_size);
        // offset += pub_key_size;
        fprintf(stderr, "Before offset");

        size_t offset = serialize_tlv(buf, );
        offset += serialize_tlv(buf+offset, nonceTLV);
        offset += serialize_tlv(buf+offset, certTLV);
        offset += serialize_tlv(buf+offset, pubKeyTLV);

        fprintf(stderr, "After offset");
        
        // Sign the data using the server's private key
        uint8_t signature[128]; // Buffer large enough for the signature
        size_t sig_size = sign(signature, buf, offset);
        fprintf(stderr, "Signature size: %zu\n", sig_size);
        fprintf(stderr, "Signature: %zu\n", signature);
        free(data_to_sign);
        
        // Add handshake signature
        tlv* handshakeSigTLV = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(handshakeSigTLV, signature, sig_size);
        add_tlv(serverHello, handshakeSigTLV);
        
        // Serialize the complete Server Hello TLV into the output buffer
        uint16_t serialized_len = serialize_tlv(buf, serverHello);
        fprintf(stderr, "Serialized len: %zu\n", serialized_len);
        
        // Debug output: print the Server Hello TLV structure
        fprintf(stderr, "Server Hello TLV structure:\n");
        print_tlv_bytes(buf, serialized_len);
        fprintf(stderr, "Test %zu\n", signature);
        
        // Free the allocated TLV tree
        free_tlv(serverHello);
        
        // Transition to waiting for the client Finished message
        server_state = STATE_SERVER_WAIT_FINISHED;
        
        // Mark that we now have all the information needed to derive keys
        needs_key_derivation = 1;
        
        return serialized_len;
    } else {
        // For non-handshake data, simply pass through to IO.
        return input_io(buf, max_length);
    }
}

// output_sec() is called when data is received from the network.
void output_sec(uint8_t* buf, size_t length) {
    // Process received data based on state
    if (server_state == STATE_SERVER_WAIT_CLIENT_HELLO) {
        // Check if received message is a Client Hello
        tlv* received_tlv = deserialize_tlv(buf, length);
        if (received_tlv && received_tlv->type == CLIENT_HELLO) {
            // Store client hello for later use
            memcpy(received_client_hello, buf, length);
            received_client_hello_len = length;
            
            // Extract client nonce and public key
            tlv* nonce_tlv = get_tlv(received_tlv, NONCE);
            tlv* pubkey_tlv = get_tlv(received_tlv, PUBLIC_KEY);
            
            if (nonce_tlv && pubkey_tlv) {
                // Load client's public key
                load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
                
                // Generate server nonce
                generate_nonce(server_nonce, NONCE_SIZE);
                
                // Generate ephemeral keypair
                generate_private_key();
                derive_public_key();
                
                // Store ephemeral public key
                server_ephemeral_public_key_len = pub_key_size;
                memcpy(server_ephemeral_public_key, public_key, pub_key_size);
                
                // Transition to sending Server Hello
                server_state = STATE_SERVER_HELLO;
                
                // Free TLV
                free_tlv(received_tlv);
                
                return; // Don't forward to IO
            }
            
            free_tlv(received_tlv);
        }
    }
    
    // If we need to derive keys, do it now
    if (needs_key_derivation) {
        // Derive the shared secret
        derive_secret();
        
        // Create salt: ClientHello + ServerHello
        uint8_t* salt = malloc(received_client_hello_len + server_hello_len);
        memcpy(salt, received_client_hello, received_client_hello_len);
        memcpy(salt + received_client_hello_len, server_hello_msg, server_hello_len);
        
        // Derive the encryption and MAC keys
        derive_keys(salt, received_client_hello_len + server_hello_len);
        
        free(salt);
        needs_key_derivation = 0;
    }
    
    // For now, simply forward the received data to the underlying IO layer.
    output_io(buf, length);
}
