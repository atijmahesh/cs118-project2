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

// Global state variables
static client_state_t client_state = CLIENT_STATE_HELLO;
static server_state_t server_state = SERVER_STATE_HELLO;

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

// Static variable to store the server's ephemeral private key
static EVP_PKEY* server_ephemeral_private_key = NULL;

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

        // Start in CLIENT_STATE_HELLO
        client_state = CLIENT_STATE_HELLO;

    } else if (type == SERVER) {
        fprintf(stderr, "DEBUG (server): Starting init_sec\n");

        // Start in SERVER_STATE_HELLO
        server_state = SERVER_STATE_HELLO;
        // (Set client side to DATA just to skip any client logic on the server side)
        client_state = CLIENT_STATE_DATA;

        load_certificate("server_cert.bin");
        fprintf(stderr, "DEBUG (server): Loaded server certificate\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // CLIENT HELLO PHASE
    if (client_state == CLIENT_STATE_HELLO) {
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

        // After sending the Hello, move to FINISHED phase
        client_state = CLIENT_STATE_FINISHED;
        return serialized_len;
    }
    // SERVER HELLO PHASE
    else if (server_state == SERVER_STATE_FINISHED) {
        // Create partial Server-Hello without signature
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
    
        // Build transcript: Client-Hello TLV + Nonce TLV + Certificate TLV + Public-Key TLV
        uint8_t transcript[4096];
        size_t offset = 0;
    
        // 1. Client-Hello TLV
        memcpy(transcript, received_client_hello, received_client_hello_len);
        offset += received_client_hello_len;
        fprintf(stderr, "DEBUG (server): Added Client-Hello to transcript, length = %zu\n", received_client_hello_len);
    
        // 2. Nonce TLV
        uint8_t nonce_buf[128];
        uint16_t nonce_len = serialize_tlv(nonce_buf, nonceTLV);
        memcpy(transcript + offset, nonce_buf, nonce_len);
        offset += nonce_len;
        fprintf(stderr, "DEBUG (server): Added Nonce to transcript, length = %u\n", nonce_len);
    
        // 3. Certificate TLV
        uint8_t cert_buf[1024];
        uint16_t cert_len = serialize_tlv(cert_buf, certTLV);
        memcpy(transcript + offset, cert_buf, cert_len);
        offset += cert_len;
        fprintf(stderr, "DEBUG (server): Added Certificate to transcript, length = %u\n", cert_len);
    
        // 4. Public-Key TLV (ephemeral)
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
    
        // Add Handshake-Signature TLV
        tlv* sigTLV = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sigTLV, signature, sig_len);
        add_tlv(partialServerHello, sigTLV);
    
        // Serialize full Server-Hello
        uint16_t serialized_len = serialize_tlv(buf, partialServerHello);
        fprintf(stderr, "DEBUG (server): Full Server-Hello length = %u\n", serialized_len);
        memcpy(server_hello_msg, buf, serialized_len);
        server_hello_len = serialized_len;
    
        free_tlv(partialServerHello);

        // After sending Server Hello, move to VERIFY_HMAC phase
        server_state = SERVER_STATE_VERIFY_HMAC;
        needs_key_derivation = 1;
        return serialized_len;
    }
    // FALL THROUGH to normal IO for other states (DATA, etc.)
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    // SERVER HELLO phase
    if (server_state == SERVER_STATE_HELLO) {
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
            generate_private_key(); // Creates ephemeral private key
            derive_public_key();    // Derives ephemeral public key
            if (public_key && pub_key_size > 0) {
                server_ephemeral_public_key_len = pub_key_size;
                memcpy(server_ephemeral_public_key, public_key, pub_key_size);
                server_ephemeral_private_key = get_private_key(); // Save ephemeral private key
                fprintf(stderr, "DEBUG (server): Generated server ephemeral public key, length = %zu\n",
                        server_ephemeral_public_key_len);
            } else {
                fprintf(stderr, "DEBUG (server): Failed to generate server ephemeral public key!\n");
            }

            // Move to SERVER_STATE_FINISHED to build/send Server Hello
            server_state = SERVER_STATE_FINISHED;
            free_tlv(received_tlv);
            return;
        } else {
            fprintf(stderr, "DEBUG (server): Unexpected TLV type %02x\n", received_tlv->type);
            free_tlv(received_tlv);
            return;
        }
    }

    // CLIENT FINISHED PHASE
    if (client_state == CLIENT_STATE_FINISHED) {
        // 1) Cache the raw Server Hello bytes
        if (length <= sizeof(server_hello_msg)) {
            memcpy(server_hello_msg, buf, length);
            server_hello_len = length;
        } else {
            fprintf(stderr, "DEBUG (client): Server Hello too large to cache\n");
        }

        // 2) Parse the Server Hello TLV
        tlv* serverHello = deserialize_tlv(buf, (uint16_t)length);
        if (!serverHello) {
            fprintf(stderr, "DEBUG (client): Server Hello TLV is invalid!\n");
            // Handle error or exit
            return;
        }

        // --------------------------------------------
        // 3) Verify the certificate
        // --------------------------------------------
        //    3a) Get the certificate TLV (CERTIFICATE).
        tlv* certTLV = get_tlv(serverHello, CERTIFICATE);
        if (!certTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing certificate!\n");
            free_tlv(serverHello);
            // Possibly exit(1) if required
            return;
        }

        //    3b) Load CA’s public key for verifying the certificate
        load_ca_public_key("ca_public_key.bin");

        // TODO: 
        //   - Parse the certificate (certTLV->val) to find the DNS name (type 0xA1),
        //     the signature (type 0xA2), etc.
        //   - Compare the DNS name with `argv[1]`.
        //   - verify(...) the certificate signature using ec_ca_public_key.
        //   - If any check fails, exit with the appropriate status.

        // --------------------------------------------
        // 4) Verify the server’s handshake signature
        // --------------------------------------------
        //    4a) Get ephemeral public key from the Server Hello
        tlv* ephemeralPubKeyTLV = get_tlv(serverHello, PUBLIC_KEY);
        if (!ephemeralPubKeyTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing PUBLIC_KEY!\n");
            free_tlv(serverHello);
            // Possibly exit(1)
            return;
        }
        //    4b) Load ephemeral key for ECDH
        load_peer_public_key(ephemeralPubKeyTLV->val, ephemeralPubKeyTLV->length);

        //    4c) Get handshake signature TLV
        tlv* handshakeSigTLV = get_tlv(serverHello, HANDSHAKE_SIGNATURE);
        if (!handshakeSigTLV) {
            fprintf(stderr, "DEBUG (client): No HANDSHAKE_SIGNATURE in Server Hello!\n");
            free_tlv(serverHello);
            // Possibly exit(3)
            return;
        }

        //    4d) Recreate the transcript you expect the server to have signed.
        //        This means (Client-Hello + partial Server-Hello data).
        //        Typically, you'd do something like:
        //        1) Copy your client_hello_msg into 'transcript'
        //        2) Re-serialize serverHello WITHOUT the handshake signature TLV
        //           (you can temporarily remove handshakeSigTLV from serverHello, 
        //            or make a partial copy).
        //        3) Call verify(...) with the server’s public key (which must come 
        //           from the certificate’s public key).
        //
        // Example pseudo-code:
        //
        // uint8_t transcript[4096];
        // size_t offset = 0;
        // memcpy(transcript, client_hello_msg, client_hello_len);
        // offset += client_hello_len;
        //
        // // Remove handshakeSigTLV from serverHello, or create a partial TLV:
        // //    remove_tlv(serverHello, handshakeSigTLV); // you’d need a custom function
        // //    or build a clone of serverHello minus that TLV
        // //    or directly piece together from the known fields.
        // // Then:
        // // offset += serialize_tlv(transcript + offset, serverHelloMinusSig);
        //
        // int verified = verify(handshakeSigTLV->val, handshakeSigTLV->length,
        //                       transcript, offset,
        //                       /*public key from the server certificate (ec_peer_public_key?)*/);
        // if (verified != 1) {
        //     fprintf(stderr, "DEBUG (client): Handshake signature verify failed.\n");
        //     exit(3);
        // }

        // --------------------------------------------
        // 5) Now that ephemeral public key is verified, do the ECDH
        // --------------------------------------------
        derive_secret();

        // --------------------------------------------
        // 6) Use HKDF to derive ENC and MAC keys
        // --------------------------------------------
        //    We do that by combining the client_hello + server_hello as salt
        uint8_t* salt = malloc(client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (client): Malloc for salt failed!\n");
            free_tlv(serverHello);
            return;
        }
        memcpy(salt, client_hello_msg, client_hello_len);
        memcpy(salt + client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, client_hello_len + server_hello_len);

        // --------------------------------------------
        // 7) Build the FINISHED message
        // --------------------------------------------
        //    7a) We want an HMAC of (Client-Hello + Server-Hello)
        uint8_t transcript_digest[MAC_SIZE]; // 32 bytes if using SHA-256
        hmac(transcript_digest, salt, client_hello_len + server_hello_len);

        free(salt); // Done using salt

        //    7b) Create the transcript TLV (type TRANSCRIPT)
        tlv* transcriptTLV = create_tlv(TRANSCRIPT);
        add_val(transcriptTLV, transcript_digest, MAC_SIZE);

        //    7c) Wrap it in a FINISHED TLV (type FINISHED)
        tlv* finishedTLV = create_tlv(FINISHED);
        add_tlv(finishedTLV, transcriptTLV);

        //    7d) Serialize the FINISHED message
        uint8_t finished_buf[256];
        uint16_t finished_len = serialize_tlv(finished_buf, finishedTLV);

        // 8) Send the FINISHED message to the server
        //    Use your existing output layer function
        output_io(finished_buf, finished_len);

        // Cleanup
        free_tlv(finishedTLV);
        free_tlv(serverHello);

        // 9) Transition to DATA phase
        client_state = CLIENT_STATE_DATA;

        return;
    }


    // ---------------------------------------------------------------------
    // SERVER: VERIFY_HMAC phase
    // ---------------------------------------------------------------------
    if (server_state == SERVER_STATE_VERIFY_HMAC && needs_key_derivation) {
        // The server sets its private key to the ephemeral one, derives secrets
        set_private_key(server_ephemeral_private_key);
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

        // TODO: Compare received HMAC with generated one (once FINISHED msg is parsed).
        //       If successful, move to DATA phase.

        needs_key_derivation = 0;
        server_state = SERVER_STATE_DATA; 
        // or remain in VERIFY_HMAC until the FINISHED message is fully processed
    }

    // CLIENT/SERVER: DATA phase
    if (client_state == CLIENT_STATE_DATA || server_state == SERVER_STATE_DATA) {
        // TODO: Implement normal encrypted data handling
        //       - For receive: decrypt and verify HMAC
        //       - For send: encrypt, add HMAC
    }
    // In all cases, default to existing output_io for sending
    output_io(buf, length);
}