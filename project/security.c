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
static int client_server_hello_verified = 0; // Flag to trigger FINISHED in input_sec

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
    } else if (type == SERVER) {
        fprintf(stderr, "DEBUG (server): Starting init_sec\n");
        server_state = SERVER_STATE_HELLO;
        client_state = CLIENT_STATE_DATA; // Disable client logic on server
        load_certificate("server_cert.bin");
        fprintf(stderr, "DEBUG (server): Loaded server certificate\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    fprintf(stderr, "DEBUG: input_sec called, client_state = %d, server_state = %d, max_length = %zu\n",
            client_state, server_state, max_length);

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
        free_tlv(clientHello);

        client_state = CLIENT_STATE_FINISHED;
        return serialized_len;
    } 
    else if (g_type == CLIENT && client_state == CLIENT_STATE_FINISHED && client_server_hello_verified) {
        // Build and send FINISHED message
        uint8_t* salt = malloc(client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (client): Malloc for salt failed!\n");
            return 0;
        }
        memcpy(salt, client_hello_msg, client_hello_len);
        memcpy(salt + client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, client_hello_len + server_hello_len);

        uint8_t transcript_digest[MAC_SIZE];
        hmac(transcript_digest, salt, client_hello_len + server_hello_len);
        free(salt);
        fprintf(stderr, "DEBUG (client): Computed HMAC for FINISHED message\n");

        tlv* transcriptTLV = create_tlv(TRANSCRIPT);
        add_val(transcriptTLV, transcript_digest, MAC_SIZE);

        tlv* finishedTLV = create_tlv(FINISHED);
        add_tlv(finishedTLV, transcriptTLV);

        uint16_t finished_len = serialize_tlv(buf, finishedTLV);
        if (finished_len > max_length) {
            fprintf(stderr, "DEBUG (client): FINISHED message exceeds max_length (%zu > %zu)\n", finished_len, max_length);
            free_tlv(finishedTLV);
            return 0;
        }
        fprintf(stderr, "DEBUG (client): Serialized FINISHED message, length = %u\n", finished_len);

        free_tlv(finishedTLV);
        client_state = CLIENT_STATE_DATA;
        fprintf(stderr, "DEBUG (client): Sent FINISHED message to server, transitioned to CLIENT_STATE_DATA\n");

        return finished_len;
    }
    else if (g_type == SERVER && server_state == SERVER_STATE_FINISHED) {
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
    
        load_private_key("server_key.bin");
        uint8_t signature[128];
        size_t sig_len = sign(signature, transcript, offset);
        fprintf(stderr, "DEBUG (server): Signature length = %zu\n", sig_len);
    
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
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
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

    if (g_type == CLIENT && client_state == CLIENT_STATE_FINISHED) {
        fprintf(stderr, "DEBUG (client): Entering CLIENT_STATE_FINISHED\n");
        fprintf(stderr, "DEBUG (client): Received buffer length: %zu\n", length);
        if (length <= sizeof(server_hello_msg)) {
            memcpy(server_hello_msg, buf, length);
            server_hello_len = length;
            fprintf(stderr, "DEBUG (client): Cached Server Hello, length = %zu\n", server_hello_len);
        } else {
            fprintf(stderr, "DEBUG (client): Server Hello too large to cache (length = %zu, max = %zu)\n", 
                    length, sizeof(server_hello_msg));
        }
    
        fprintf(stderr, "DEBUG (client): Attempting to deserialize Server Hello\n");
        tlv* serverHello = deserialize_tlv(buf, (uint16_t)length);
        if (!serverHello) {
            fprintf(stderr, "DEBUG (client): Server Hello TLV is invalid! Dumping buffer:\n");
            print_tlv_bytes(buf, length);
            return;
        }
        fprintf(stderr, "DEBUG (client): Successfully parsed Server Hello, type = 0x%02x\n", serverHello->type);
    
        fprintf(stderr, "DEBUG (client): Checking for CERTIFICATE TLV\n");
        tlv* certTLV = get_tlv(serverHello, CERTIFICATE);
        if (!certTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing certificate!\n");
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Found CERTIFICATE TLV\n");
    
        load_ca_public_key("ca_public_key.bin");
        fprintf(stderr, "DEBUG (client): Loaded CA public key\n");
    
        fprintf(stderr, "DEBUG (client): Checking for DNS_NAME and SIGNATURE TLVs in certificate\n");
        tlv* dnsNameTLV = get_tlv(certTLV, DNS_NAME);
        tlv* certSignatureTLV = get_tlv(certTLV, SIGNATURE);
    
        if (!dnsNameTLV) {
            fprintf(stderr, "DEBUG (client): Certificate missing DNS_NAME (0xA1)!\n");
            free_tlv(serverHello);
            exit(2);
        }
        if (!certSignatureTLV) {
            fprintf(stderr, "DEBUG (client): Certificate missing SIGNATURE (0xA2)!\n");
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Found DNS_NAME and SIGNATURE TLVs\n");
    
        size_t host_len = strlen(g_host);
        fprintf(stderr, "DEBUG (client): Verifying DNS name: Expected '%s' (length %zu), Got '%.*s' (length %u)\n", 
                g_host, host_len, (int)dnsNameTLV->length, dnsNameTLV->val, dnsNameTLV->length);
        fprintf(stderr, "DEBUG (client): Expected bytes: ");
        for (size_t i = 0; i < host_len; i++) {
            fprintf(stderr, "%02x ", (unsigned char)g_host[i]);
        }
        fprintf(stderr, "\nDEBUG (client): Got bytes: ");
        for (size_t i = 0; i < dnsNameTLV->length; i++) {
            fprintf(stderr, "%02x ", (unsigned char)dnsNameTLV->val[i]);
        }
        fprintf(stderr, "\n");
        if (dnsNameTLV->length < host_len || 
            (dnsNameTLV->length > host_len + 1) || 
            memcmp(dnsNameTLV->val, g_host, host_len) != 0 || 
            (dnsNameTLV->length == host_len + 1 && dnsNameTLV->val[host_len] != 0)) {
            fprintf(stderr, "DEBUG (client): DNS name mismatch. Expected: %s (length %zu), Got: %.*s (length %u)\n", 
                    g_host, host_len, (int)dnsNameTLV->length, dnsNameTLV->val, dnsNameTLV->length);
            free_tlv(serverHello);
            exit(2);
        }
        fprintf(stderr, "DEBUG (client): DNS name verified successfully\n");
    
        // Verify the certificate
        fprintf(stderr, "DEBUG (client): Deserializing certificate inner TLVs, length = %u\n", certTLV->length);
        fprintf(stderr, "DEBUG (client): Dumping certTLV->val before deserialization:\n");
        print_tlv_bytes(certTLV->val, certTLV->length);
        tlv* certInnerTLVs = deserialize_tlv(certTLV->val, certTLV->length);
        if (!certInnerTLVs) {
            fprintf(stderr, "DEBUG (client): Failed to deserialize certificate inner TLVs!\n");
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Successfully deserialized certificate inner TLVs\n");
    
        tlv* certPubKeyTLV = get_tlv(certInnerTLVs, PUBLIC_KEY);
        if (!certPubKeyTLV) {
            fprintf(stderr, "DEBUG (client): Certificate missing PUBLIC_KEY!\n");
            free_tlv(certInnerTLVs);
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Found PUBLIC_KEY in certificate, length = %u\n", certPubKeyTLV->length);
        tlv* certDNSTLV = get_tlv(certInnerTLVs, DNS_NAME);
        if (!certDNSTLV) {
            fprintf(stderr, "DEBUG (client): Certificate missing DNS_NAME in inner TLVs!\n");
            free_tlv(certInnerTLVs);
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Found DNS_NAME in certificate, length = %u\n", certDNSTLV->length);
    
        tlv* partialCert = create_tlv(CERTIFICATE);
        add_tlv(partialCert, certPubKeyTLV);
        add_tlv(partialCert, certDNSTLV);
    
        uint8_t certData[1024];
        uint16_t certDataLen = serialize_tlv(certData, partialCert);
        fprintf(stderr, "DEBUG (client): Serialized certificate data for verification, length = %u\n", certDataLen);
    
        int verify_result = verify(certSignatureTLV->val, certSignatureTLV->length, certData, certDataLen, ec_ca_public_key);
        free_tlv(partialCert);
        free_tlv(certInnerTLVs);
    
        if (verify_result != 1) {
            fprintf(stderr, "DEBUG (client): CA signature verification on certificate failed! (Result: %d)\n", verify_result);
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Certificate verified successfully!\n");
    
        fprintf(stderr, "DEBUG (client): Checking for PUBLIC_KEY TLV\n");
        tlv* ephemeralPubKeyTLV = get_tlv(serverHello, PUBLIC_KEY);
        if (!ephemeralPubKeyTLV) {
            fprintf(stderr, "DEBUG (client): Server Hello missing PUBLIC_KEY!\n");
            free_tlv(serverHello);
            exit(1);
        }
        fprintf(stderr, "DEBUG (client): Found PUBLIC_KEY TLV, length = %u\n", ephemeralPubKeyTLV->length);
        load_peer_public_key(ephemeralPubKeyTLV->val, ephemeralPubKeyTLV->length);
        fprintf(stderr, "DEBUG (client): Loaded ephemeral public key for ECDH\n");
    
        fprintf(stderr, "DEBUG (client): Checking for HANDSHAKE_SIGNATURE TLV\n");
        tlv* handshakeSigTLV = get_tlv(serverHello, HANDSHAKE_SIGNATURE);
        if (!handshakeSigTLV) {
            fprintf(stderr, "DEBUG (client): No HANDSHAKE_SIGNATURE in Server Hello!\n");
            free_tlv(serverHello);
            exit(3);
        }
        fprintf(stderr, "DEBUG (client): Found HANDSHAKE_SIGNATURE TLV, length = %u\n", handshakeSigTLV->length);
    
        uint8_t transcript[4096];
        size_t offset = 0;
        memcpy(transcript, client_hello_msg, client_hello_len);
        offset += client_hello_len;
        fprintf(stderr, "DEBUG (client): Added Client Hello to transcript, offset = %zu\n", offset);
    
        tlv* partialServerHello = create_tlv(SERVER_HELLO);
        tlv* nonceTLV = get_tlv(serverHello, NONCE);
        if (nonceTLV) {
            tlv* nonceCopy = create_tlv(NONCE);
            add_val(nonceCopy, nonceTLV->val, nonceTLV->length);
            add_tlv(partialServerHello, nonceCopy);
            fprintf(stderr, "DEBUG (client): Added NONCE to partial Server Hello\n");
        }
        if (certTLV) {
            tlv* certCopy = create_tlv(CERTIFICATE);
            add_val(certCopy, certTLV->val, certTLV->length);
            add_tlv(partialServerHello, certCopy);
            fprintf(stderr, "DEBUG (client): Added CERTIFICATE to partial Server Hello\n");
        }
        if (ephemeralPubKeyTLV) {
            tlv* pubKeyCopy = create_tlv(PUBLIC_KEY);
            add_val(pubKeyCopy, ephemeralPubKeyTLV->val, ephemeralPubKeyTLV->length);
            add_tlv(partialServerHello, pubKeyCopy);
            fprintf(stderr, "DEBUG (client): Added PUBLIC_KEY to partial Server Hello\n");
        }
    
        uint16_t partialServerHelloLen = serialize_tlv(transcript + offset, partialServerHello);
        offset += partialServerHelloLen;
        fprintf(stderr, "DEBUG (client): Transcript length for handshake verification: %zu\n", offset);
    
        fprintf(stderr, "DEBUG (client): Loading server public key for handshake verification\n");
        load_peer_public_key(certPubKeyTLV->val, certPubKeyTLV->length);
        int handshake_verify_result = verify(handshakeSigTLV->val, handshakeSigTLV->length, transcript, offset, ec_peer_public_key);
        free_tlv(partialServerHello);
    
        if (handshake_verify_result != 1) {
            fprintf(stderr, "DEBUG (client): Handshake signature verification failed! (Result: %d)\n", handshake_verify_result);
            free_tlv(serverHello);
            exit(3);
        }
        fprintf(stderr, "DEBUG (client): Handshake signature verified successfully!\n");
    
        fprintf(stderr, "DEBUG (client): Deriving shared secret\n");
        load_peer_public_key(ephemeralPubKeyTLV->val, ephemeralPubKeyTLV->length);
        derive_secret();
    
        uint8_t* salt = malloc(client_hello_len + server_hello_len);
        if (!salt) {
            fprintf(stderr, "DEBUG (client): Failed to allocate salt!\n");
            free_tlv(serverHello);
            exit(1);
        }
        memcpy(salt, client_hello_msg, client_hello_len);
        memcpy(salt + client_hello_len, server_hello_msg, server_hello_len);
        derive_keys(salt, client_hello_len + server_hello_len);
        free(salt);
        fprintf(stderr, "DEBUG (client): Derived ENC and MAC keys\n");
    
        free_tlv(serverHello);
        client_server_hello_verified = 1;
        fprintf(stderr, "DEBUG (client): Set client_server_hello_verified, signaling FINISHED\n");
        uint8_t dummy[1] = {0};
        output_io(dummy, 1); // Send a non-zero length to force transport layer action
        fprintf(stderr, "DEBUG (client): Called output_io to trigger input_sec\n");
        return;
    }

    if (g_type == SERVER && server_state == SERVER_STATE_VERIFY_HMAC) {
        fprintf(stderr, "DEBUG (server): Received data in VERIFY_HMAC, length = %zu\n", length);
        tlv* finishedTLV = deserialize_tlv(buf, (uint16_t)length);
        if (!finishedTLV || finishedTLV->type != FINISHED) {
            fprintf(stderr, "DEBUG (server): Invalid or missing FINISHED TLV\n");
            free_tlv(finishedTLV);
            return;
        }
        tlv* transcriptTLV = get_tlv(finishedTLV, TRANSCRIPT);
        if (!transcriptTLV || transcriptTLV->length != MAC_SIZE) {
            fprintf(stderr, "DEBUG (server): Invalid TRANSCRIPT TLV\n");
            free_tlv(finishedTLV);
            return;
        }

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

        uint8_t computed_digest[MAC_SIZE];
        hmac(computed_digest, salt, received_client_hello_len + server_hello_len);
        free(salt);

        if (memcmp(transcriptTLV->val, computed_digest, MAC_SIZE) != 0) {
            fprintf(stderr, "DEBUG (server): HMAC verification failed!\n");
            free_tlv(finishedTLV);
            exit(1);
        }
        fprintf(stderr, "DEBUG (server): HMAC verified successfully\n");

        needs_key_derivation = 0;
        server_state = SERVER_STATE_DATA;
        fprintf(stderr, "DEBUG (server): Transitioned to SERVER_STATE_DATA\n");
        free_tlv(finishedTLV);
        return;
    }

    if (g_type == CLIENT && client_state == CLIENT_STATE_DATA || 
        g_type == SERVER && server_state == SERVER_STATE_DATA) {
        // TODO: Implement encrypted data handling
    }
    output_io(buf, length);
}