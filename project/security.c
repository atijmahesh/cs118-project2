#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// client and server states
typedef enum {
    CLIENT_STATE_HELLO, 
    CLIENT_STATE_FINISHED,
    CLIENT_STATE_DATA 
} client_state_t;

typedef enum {
    SERVER_STATE_HELLO,   
    SERVER_STATE_FINISHED,   
    SERVER_STATE_VERIFY_HMAC, 
    SERVER_STATE_DATA    
} server_state_t;

// Global state variables and globals from new version
static client_state_t client_state = CLIENT_STATE_HELLO;
static server_state_t server_state = SERVER_STATE_HELLO;
static char g_host[256] = {0};
static int g_type = -1; // -1: uninitialized, 0: CLIENT, 1: SERVER

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
// Flag used in some attempted new logic; not used to gate sending FINISHED here.
static int client_server_hello_verified = 0;

// Static variable to store the server's ephemeral private key
static EVP_PKEY* server_ephemeral_private_key = NULL;

void init_sec(int type, char* host) {
    init_io();
    g_type = type;
    if (host != NULL) {
        strncpy(g_host, host, sizeof(g_host) - 1);
        g_host[sizeof(g_host) - 1] = '\0';
    }

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
        client_state = CLIENT_STATE_HELLO;
        load_ca_public_key("ca_public_key.bin"); // Load CA public key for certificate verification
    } else if (type == SERVER) {
        fprintf(stderr, "DEBUG (server): Starting init_sec\n");
        server_state = SERVER_STATE_HELLO;
        client_state = CLIENT_STATE_DATA; // Disable client logic on server
        load_certificate("server_cert.bin");
        fprintf(stderr, "DEBUG (server): Loaded server certificate\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // CLIENT HELLO PHASE: send Client Hello
    if (g_type == CLIENT && client_state == CLIENT_STATE_HELLO) {
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
        // (Optional debug print)
        print_tlv_bytes(buf, serialized_len);
        free_tlv(clientHello);
        // Move to FINISHED phase; finished message will be sent in output_sec
        client_state = CLIENT_STATE_FINISHED;
        return serialized_len;
    }
    // SERVER HELLO PHASE (for server)
    else if (g_type == SERVER && server_state == SERVER_STATE_FINISHED) {
        // Build partial Server-Hello without signature (as in your old code)
        tlv* partialServerHello = create_tlv(SERVER_HELLO);
        tlv* nonceTLV = create_tlv(NONCE);
        add_val(nonceTLV, server_nonce, NONCE_SIZE);
        add_tlv(partialServerHello, nonceTLV);
        tlv* certTLV = deserialize_tlv(certificate, cert_size);
        if (!certTLV) {
            fprintf(stderr, "DEBUG (server): Failed to deserialize certificate TLV\n");
            free_tlv(partialServerHello);
            return 0;
        }
        add_tlv(partialServerHello, certTLV);
        tlv* ephemeralPubTLV = create_tlv(PUBLIC_KEY);
        add_val(ephemeralPubTLV, server_ephemeral_public_key, server_ephemeral_public_key_len);
        add_tlv(partialServerHello, ephemeralPubTLV);
    
        uint8_t transcript[4096];
        size_t offset = 0;
        memcpy(transcript, received_client_hello, received_client_hello_len);
        offset += received_client_hello_len;
        fprintf(stderr, "DEBUG (server): Added Client-Hello to transcript, length = %zu\n", received_client_hello_len);
    
        uint8_t nonce_buf[128];
        uint16_t nonce_len = serialize_tlv(nonce_buf, nonceTLV);
        memcpy(transcript + offset, nonce_buf, nonce_len);
        offset += nonce_len;
        fprintf(stderr, "DEBUG (server): Added Nonce to transcript, length = %u\n", nonce_len);
    
        uint8_t cert_buf[1024];
        uint16_t cert_len = serialize_tlv(cert_buf, certTLV);
        memcpy(transcript + offset, cert_buf, cert_len);
        offset += cert_len;
        fprintf(stderr, "DEBUG (server): Added Certificate to transcript, length = %u\n", cert_len);
    
        uint8_t pubkey_buf[256];
        uint16_t pubkey_len = serialize_tlv(pubkey_buf, ephemeralPubTLV);
        memcpy(transcript + offset, pubkey_buf, pubkey_len);
        offset += pubkey_len;
        fprintf(stderr, "DEBUG (server): Added Public-Key to transcript, length = %u\n", pubkey_len);
    
        fprintf(stderr, "DEBUG (server): Total transcript length = %zu\n", offset);
    
        // Sign the transcript
        load_private_key("server_key.bin");
        uint8_t signature[128];
        size_t sig_len = sign(signature, transcript, offset);
        fprintf(stderr, "DEBUG (server): Signature length = %zu\n", sig_len);
    
        // Restore the ephemeral private key
        set_private_key(server_ephemeral_private_key);
    
        tlv* sigTLV = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sigTLV, signature, sig_len);
        add_tlv(partialServerHello, sigTLV);
    
        uint16_t serialized_len = serialize_tlv(buf, partialServerHello);
        fprintf(stderr, "DEBUG (server): Full Server-Hello length = %u\n", serialized_len);
        memcpy(server_hello_msg, buf, serialized_len);
        server_hello_len = serialized_len;
        free_tlv(partialServerHello);
    
        server_state = SERVER_STATE_VERIFY_HMAC;
        needs_key_derivation = 1;
        return serialized_len;
    }
    // Fallback to underlying I/O
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    // SERVER side: process incoming Client Hello, etc.
    if (g_type == SERVER && server_state == SERVER_STATE_HELLO) {
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
    
            // Generate ephemeral key pair
            generate_private_key();
            derive_public_key();
            if (public_key && pub_key_size > 0) {
                server_ephemeral_public_key_len = pub_key_size;
                memcpy(server_ephemeral_public_key, public_key, pub_key_size);
                server_ephemeral_private_key = get_private_key();
                fprintf(stderr, "DEBUG (server): Generated server ephemeral public key, length = %zu\n",
                        server_ephemeral_public_key_len);
            } else {
                fprintf(stderr, "DEBUG (server): Failed to generate server ephemeral public key!\n");
            }
    
            server_state = SERVER_STATE_FINISHED;
            free_tlv(received_tlv);
            return;
        } else {
            fprintf(stderr, "DEBUG (server): Unexpected TLV type %02x\n", received_tlv->type);
            free_tlv(received_tlv);
            return;
        }
    }
    
    // CLIENT FINISHED PHASE: process Server Hello and send FINISHED message
    if (g_type == CLIENT && client_state == CLIENT_STATE_FINISHED) {
        // Cache the raw Server Hello bytes
        if (length <= sizeof(server_hello_msg)) {
            memcpy(server_hello_msg, buf, length);
            server_hello_len = length;
        } else {
            fprintf(stderr, "DEBUG (client): Server Hello too large to cache\n");
            return;
        }

        // Parse the Server Hello TLV
        tlv* serverHello = deserialize_tlv(buf, (uint16_t)length);
        if (!serverHello || serverHello->type != SERVER_HELLO) {
            fprintf(stderr, "DEBUG (client): Server Hello TLV is invalid or unexpected type!\n");
            free_tlv(serverHello);
            exit(6); // Unexpected message per spec
        }

        // Extract certificate TLV
        tlv* certTLV = get_tlv(serverHello, CERTIFICATE);
        if (!certTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing certificate!\n");
            free_tlv(serverHello);
            return;
        }

        // Parse certificate TLV
        tlv* dnsTLV = get_tlv(certTLV, DNS_NAME);
        tlv* serverPubKeyTLV = get_tlv(certTLV, PUBLIC_KEY);
        tlv* certSigTLV = get_tlv(certTLV, SIGNATURE);
        if (!dnsTLV || !serverPubKeyTLV || !certSigTLV) {
            fprintf(stderr, "DEBUG (client): Certificate missing required fields!\n");
            free_tlv(serverHello);
            return;
        }

        // Verify certificate signature
        uint8_t cert_data[1024];
        size_t cert_data_len = 0;
        uint16_t dns_len = serialize_tlv(cert_data, dnsTLV);
        cert_data_len += dns_len;
        uint16_t pubkey_len = serialize_tlv(cert_data + cert_data_len, serverPubKeyTLV);
        cert_data_len += pubkey_len;
        int verify_result = verify(certSigTLV->val, certSigTLV->length, cert_data, cert_data_len, ec_ca_public_key);
        if (verify_result != 1) {
            fprintf(stderr, "DEBUG (client): Certificate signature verification failed!\n");
            free_tlv(serverHello);
            exit(1); // Per spec
        }

        
        // Check DNS name
        char dns_name[256];
        if (dnsTLV->length >= sizeof(dns_name)) {
            fprintf(stderr, "DEBUG (client): DNS name too long\n");
            free_tlv(serverHello);
            exit(2); // Per spec
        }
        memcpy(dns_name, dnsTLV->val, dnsTLV->length);
        dns_name[dnsTLV->length] = '\0'; // Null-terminate

        if (strcmp(dns_name, g_host) != 0) {
            fprintf(stderr, "DEBUG (client): DNS name mismatch! Expected '%s', got '%s'\n",
                    g_host, dns_name);
            free_tlv(serverHello);
            exit(2); // Per spec
        }

        // Get signature TLV from Server Hello
        tlv* sigTLV = get_tlv(serverHello, HANDSHAKE_SIGNATURE);
        if (!sigTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing signature!\n");
            free_tlv(serverHello);
            return;
        }

        // Get other TLVs for transcript
        tlv* serverNonceTLV = get_tlv(serverHello, NONCE);
        tlv* serverEphemeralPubTLV = get_tlv(serverHello, PUBLIC_KEY);
        if (!serverNonceTLV || !serverEphemeralPubTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing required fields!\n");
            free_tlv(serverHello);
            return;
        }

        // Build transcript for Server Hello signature verification
        uint8_t transcript[4096];
        size_t offset = 0;
        memcpy(transcript, client_hello_msg, client_hello_len);
        offset += client_hello_len;
        uint8_t server_nonce_buf[128];
        uint16_t server_nonce_len = serialize_tlv(server_nonce_buf, serverNonceTLV);
        memcpy(transcript + offset, server_nonce_buf, server_nonce_len);
        offset += server_nonce_len;
        uint8_t cert_buf[1024];
        uint16_t cert_len = serialize_tlv(cert_buf, certTLV);
        memcpy(transcript + offset, cert_buf, cert_len);
        offset += cert_len;
        uint8_t server_pubkey_buf[256];
        uint16_t server_pubkey_len = serialize_tlv(server_pubkey_buf, serverEphemeralPubTLV);
        memcpy(transcript + offset, server_pubkey_buf, server_pubkey_len);
        offset += server_pubkey_len;

        // Verify Server Hello signature using server's long-term public key
        load_peer_public_key(serverPubKeyTLV->val, serverPubKeyTLV->length);
        verify_result = verify(sigTLV->val, sigTLV->length, transcript, offset, ec_peer_public_key);
        if (verify_result != 1) {
            fprintf(stderr, "DEBUG (client): Server Hello signature verification failed!\n");
            free_tlv(serverHello);
            exit(3); // Per spec
        }

        // Derive shared secret and keys using server's ephemeral public key
        load_peer_public_key(serverEphemeralPubTLV->val, serverEphemeralPubTLV->length);
        derive_secret();
        uint8_t* salt = malloc(client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (client): Malloc for salt failed!\n");
            free_tlv(serverHello);
            return;
        }
        memcpy(salt, client_hello_msg, client_hello_len);
        memcpy(salt + client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, client_hello_len + server_hello_len);

        // Compute transcript HMAC for FINISHED message
        uint8_t transcript_digest[MAC_SIZE];
        hmac(transcript_digest, salt, client_hello_len + server_hello_len);
        free(salt);

        // Build FINISHED message
        tlv* transcriptTLV = create_tlv(TRANSCRIPT);
        add_val(transcriptTLV, transcript_digest, MAC_SIZE);
        tlv* finishedTLV = create_tlv(FINISHED);
        add_tlv(finishedTLV, transcriptTLV);
        uint8_t finished_buf[256];
        uint16_t finished_len = serialize_tlv(finished_buf, finishedTLV);

        // Send FINISHED message
        output_io(finished_buf, finished_len);
        fprintf(stderr, "DEBUG (client): Sent FINISHED message, length = %u\n", finished_len);

        free_tlv(finishedTLV);
        free_tlv(serverHello);

        client_state = CLIENT_STATE_DATA;
        return;
    }
    
    // SERVER: VERIFY_HMAC phase
    if (g_type == SERVER && server_state == SERVER_STATE_VERIFY_HMAC) {
        tlv* finishedTLV = deserialize_tlv(buf, length);
        if (!finishedTLV || finishedTLV->type != FINISHED) {
            fprintf(stderr, "DEBUG (server): Expected FINISHED message, got type %02x\n",
                    finishedTLV ? finishedTLV->type : 0);
            free_tlv(finishedTLV);
            exit(6); // Unexpected message per spec
        }
        tlv* transcriptTLV = get_tlv(finishedTLV, TRANSCRIPT);
        if (!transcriptTLV || transcriptTLV->length != MAC_SIZE) {
            fprintf(stderr, "DEBUG (server): Invalid TRANSCRIPT in FINISHED message\n");
            free_tlv(finishedTLV);
            exit(4); // Per spec
        }

        // Derive keys
        set_private_key(server_ephemeral_private_key);
        derive_secret();
        uint8_t* salt = malloc(received_client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (server): Salt allocation failed\n");
            free_tlv(finishedTLV);
            return;
        }
        memcpy(salt, received_client_hello, received_client_hello_len);
        memcpy(salt + received_client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, received_client_hello_len + server_hello_len);

        // Compute expected HMAC
        uint8_t expected_digest[MAC_SIZE];
        hmac(expected_digest, salt, received_client_hello_len + server_hello_len);
        free(salt);

        // Compare with received transcript
        if (memcmp(transcriptTLV->val, expected_digest, MAC_SIZE) != 0) {
            fprintf(stderr, "DEBUG (server): HMAC verification failed\n");
            free_tlv(finishedTLV);
            exit(4); // Per spec
        }

        free_tlv(finishedTLV);
        needs_key_derivation = 0;
        server_state = SERVER_STATE_DATA;
        fprintf(stderr, "DEBUG (server): HMAC verified, transitioning to DATA state\n");
        return;
    }
    
    // DATA phase (client or server) - normal encrypted data handling
    output_io(buf, length);
}
