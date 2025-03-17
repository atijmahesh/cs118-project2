#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Client and server states
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
static int g_type = -1; // -1 uninitialized, 0 CLIENT, 1 SERVER

// Client handshake buffers
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t client_public_key[512];
static size_t client_public_key_len = 0;
static uint8_t finished_buf[256];
static size_t finished_len = 0;

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
static int handshake_complete = 0;

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
        generate_private_key();
        derive_public_key();
        if (public_key && pub_key_size > 0) {
            client_public_key_len = pub_key_size;
            memcpy(client_public_key, public_key, client_public_key_len);
        } else {
            fprintf(stderr, "DEBUG (client): Failed to generate client ephemeral public key!\n");
        }
        generate_nonce(client_nonce, NONCE_SIZE);
        client_state = CLIENT_STATE_HELLO;
        load_ca_public_key("ca_public_key.bin");
    }
    else if (type == SERVER) {
        fprintf(stderr, "DEBUG (server): Starting init_sec\n");
        server_state = SERVER_STATE_HELLO;
        client_state = CLIENT_STATE_DATA; // Disable client logic on server
        load_certificate("server_cert.bin");
        fprintf(stderr, "DEBUG (server): Loaded server certificate\n");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (g_type == CLIENT) {
        if (client_state == CLIENT_STATE_HELLO) {
            // Send Client Hello
            tlv* clientHello = create_tlv(CLIENT_HELLO);
            tlv* nonceTLV = create_tlv(NONCE);
            add_val(nonceTLV, client_nonce, NONCE_SIZE);
            add_tlv(clientHello, nonceTLV);
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
        } else if (client_state == CLIENT_STATE_FINISHED && finished_len > 0) {
            // Send FINISHED message as a standalone packet
            if (finished_len > max_length) {
                fprintf(stderr, "DEBUG (client): FINISHED message too large for buffer\n");
                return 0;
            }
            memcpy(buf, finished_buf, finished_len);
            size_t len = finished_len;
            finished_len = 0; // Reset after sending
            handshake_complete = 1;
            client_state = CLIENT_STATE_DATA;
            return len;
        } else if (client_state == CLIENT_STATE_DATA && handshake_complete) {
            // Send encrypted data
            if (max_length < 74) { // 58 TLV overhead + 16 min ciphertext
                return 0;
            }

            size_t max_ciphertext_size = ((max_length - 58) / 16) * 16;
            size_t max_plaintext_size = max_ciphertext_size - 1;

            uint8_t plaintext[943];
            ssize_t read_len = read(STDIN_FILENO, plaintext, max_plaintext_size);
            if (read_len <= 0) {
                return 0; // No data/error
            }
            size_t plaintext_size = (size_t)read_len;

            uint8_t iv[16];
            generate_nonce(iv, 16);

            uint8_t cipher[960]; // Max ciphertext size (943 + padding)
            size_t cipher_size = encrypt_data(iv, cipher, plaintext, plaintext_size);

            tlv* ivTLV = create_tlv(IV);
            add_val(ivTLV, iv, 16);

            tlv* cipherTLV = create_tlv(CIPHERTEXT);
            add_val(cipherTLV, cipher, cipher_size);

            uint8_t iv_buf[18];
            uint16_t iv_len = serialize_tlv(iv_buf, ivTLV);
            uint8_t cipher_buf[963]; // Max cipher_size + header
            uint16_t cipher_len = serialize_tlv(cipher_buf, cipherTLV);
            uint8_t hmac_input[981]; // 18 + 963
            memcpy(hmac_input, iv_buf, iv_len);
            memcpy(hmac_input + iv_len, cipher_buf, cipher_len);
            size_t hmac_input_size = iv_len + cipher_len;

            uint8_t mac[32];
            hmac(mac, hmac_input, hmac_input_size);

            tlv* macTLV = create_tlv(MAC);
            add_val(macTLV, mac, 32);

            tlv* dataTLV = create_tlv(DATA);
            add_tlv(dataTLV, ivTLV);
            add_tlv(dataTLV, cipherTLV);
            add_tlv(dataTLV, macTLV);

            size_t data_len = serialize_tlv(buf, dataTLV);
            free_tlv(dataTLV);

            return data_len;
        }
    }
    else if (g_type == SERVER) {
        if (server_state == SERVER_STATE_FINISHED) {
            // Send Server Hello during handshake
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

            // Build transcript for signature
            uint8_t transcript[4096];
            size_t offset = 0;
            memcpy(transcript, received_client_hello, received_client_hello_len);
            offset += received_client_hello_len;
            uint8_t nonce_buf[128];
            uint16_t nonce_len = serialize_tlv(nonce_buf, nonceTLV);
            memcpy(transcript + offset, nonce_buf, nonce_len);
            offset += nonce_len;
            uint8_t cert_buf[1024];
            uint16_t cert_len = serialize_tlv(cert_buf, certTLV);
            memcpy(transcript + offset, cert_buf, cert_len);
            offset += cert_len;
            uint8_t pubkey_buf[256];
            uint16_t pubkey_len = serialize_tlv(pubkey_buf, ephemeralPubTLV);
            memcpy(transcript + offset, pubkey_buf, pubkey_len);
            offset += pubkey_len;

            // Sign the transcript
            load_private_key("server_key.bin");
            uint8_t signature[128];
            size_t sig_len = sign(signature, transcript, offset);
            set_private_key(server_ephemeral_private_key);

            tlv* sigTLV = create_tlv(HANDSHAKE_SIGNATURE);
            add_val(sigTLV, signature, sig_len);
            add_tlv(partialServerHello, sigTLV);

            // Serialize and store Server Hello
            uint16_t serialized_len = serialize_tlv(buf, partialServerHello);
            memcpy(server_hello_msg, buf, serialized_len);
            server_hello_len = serialized_len;
            free_tlv(partialServerHello);

            server_state = SERVER_STATE_VERIFY_HMAC;
            needs_key_derivation = 1;
            return serialized_len;
        }
        else if (server_state == SERVER_STATE_DATA) {
            // Read from stdin and encrypt data
            ssize_t read_len = input_io(buf, max_length);
            if (read_len <= 0) {
                fprintf(stderr, "DEBUG (server): No data read from stdin\n");
                return 0;
            }
            size_t plaintext_size = (size_t)read_len;
            uint8_t iv[16];
            generate_nonce(iv, 16);
            uint8_t cipher[960];
            size_t cipher_size = encrypt_data(iv, cipher, buf, plaintext_size);
        
            // Build DATA TLV
            tlv* ivTLV = create_tlv(IV);
            add_val(ivTLV, iv, 16);
            tlv* cipherTLV = create_tlv(CIPHERTEXT);
            add_val(cipherTLV, cipher, cipher_size);
            uint8_t iv_buf[18];
            uint16_t iv_len = serialize_tlv(iv_buf, ivTLV);
            uint8_t cipher_buf[963];
            uint16_t cipher_len = serialize_tlv(cipher_buf, cipherTLV);
            uint8_t hmac_input[981];
            memcpy(hmac_input, iv_buf, iv_len);
            memcpy(hmac_input + iv_len, cipher_buf, cipher_len);
            size_t hmac_input_size = iv_len + cipher_len;
            uint8_t mac[32];
            hmac(mac, hmac_input, hmac_input_size);
            tlv* macTLV = create_tlv(MAC);
            add_val(macTLV, mac, 32);
            tlv* dataTLV = create_tlv(DATA);
            add_tlv(dataTLV, ivTLV);
            add_tlv(dataTLV, cipherTLV);
            add_tlv(dataTLV, macTLV);
            size_t data_len = serialize_tlv(buf, dataTLV);
            free_tlv(dataTLV);
            return data_len;
        }
        else {
            return 0;
        }
    }
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    if (g_type == SERVER) {
        if (server_state == SERVER_STATE_HELLO) {
            // Process Client Hello message from the client
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
        } else if (server_state == SERVER_STATE_VERIFY_HMAC) {
            // Verify the FINISHED message from the client
            tlv* finishedTLV = deserialize_tlv(buf, length);
            if (!finishedTLV || finishedTLV->type != FINISHED) {
                fprintf(stderr, "DEBUG (server): Expected FINISHED, got %02x\n", finishedTLV ? finishedTLV->type : 0);
                free_tlv(finishedTLV);
                exit(6);
            }
            tlv* transcriptTLV = get_tlv(finishedTLV, TRANSCRIPT);
            if (!transcriptTLV || transcriptTLV->length != MAC_SIZE) {
                fprintf(stderr, "DEBUG (server): Invalid TRANSCRIPT\n");
                free_tlv(finishedTLV);
                exit(4);
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

            uint8_t expected_digest[MAC_SIZE];
            hmac(expected_digest, salt, received_client_hello_len + server_hello_len);
            free(salt);

            if (memcmp(transcriptTLV->val, expected_digest, MAC_SIZE) != 0) {
                fprintf(stderr, "DEBUG (server): HMAC verification failed\n");
                free_tlv(finishedTLV);
                exit(4);
            }

            free_tlv(finishedTLV);
            needs_key_derivation = 0;
            server_state = SERVER_STATE_DATA;
            return;
        } else if (server_state == SERVER_STATE_DATA) {
            // Receive and decrypt encrypted data from the client
            tlv* dataTLV = deserialize_tlv(buf, length);
            if (!dataTLV || dataTLV->type != DATA) {
                fprintf(stderr, "DEBUG (server): Expected DATA TLV, got %02x\n", dataTLV ? dataTLV->type : 0);
                output_io(buf, length); // Fall back to unencrypted data
                free_tlv(dataTLV);
                return;
            }

            tlv* ivTLV = get_tlv(dataTLV, IV);
            tlv* cipherTLV = get_tlv(dataTLV, CIPHERTEXT);
            tlv* macTLV = get_tlv(dataTLV, MAC);
            if (!ivTLV || ivTLV->length != 16 || !cipherTLV || !macTLV || macTLV->length != 32) {
                fprintf(stderr, "DEBUG (server): Missing or invalid TLVs in DATA\n");
                free_tlv(dataTLV);
                exit(5);
            }

            uint8_t iv_buf[18];
            uint16_t iv_len = serialize_tlv(iv_buf, ivTLV);
            uint8_t cipher_buf[963];
            uint16_t cipher_len = serialize_tlv(cipher_buf, cipherTLV);
            uint8_t hmac_input[981];
            memcpy(hmac_input, iv_buf, iv_len);
            memcpy(hmac_input + iv_len, cipher_buf, cipher_len);
            size_t hmac_input_size = iv_len + cipher_len;

            uint8_t computed_mac[32];
            hmac(computed_mac, hmac_input, hmac_input_size);

            if (memcmp(macTLV->val, computed_mac, 32) != 0) {
                fprintf(stderr, "DEBUG (server): HMAC verification failed\n");
                free_tlv(dataTLV);
                exit(5);
            }

            uint8_t plaintext[960];
            size_t plaintext_size = decrypt_cipher(plaintext, cipherTLV->val, cipherTLV->length, ivTLV->val);

            write(STDOUT_FILENO, plaintext, plaintext_size);
            free_tlv(dataTLV);
            return;
        }
    } else if (g_type == CLIENT) {
        if (client_state == CLIENT_STATE_FINISHED && finished_len == 0) {
            // Process Server Hello and prepare FINISHED message
            if (length > sizeof(server_hello_msg)) {
                fprintf(stderr, "DEBUG (client): Server Hello too large\n");
                return;
            }
            memcpy(server_hello_msg, buf, length);
            server_hello_len = length;

            tlv* serverHello = deserialize_tlv(buf, length);
            if (!serverHello || serverHello->type != SERVER_HELLO) {
                fprintf(stderr, "DEBUG (client): Invalid Server Hello\n");
                free_tlv(serverHello);
                exit(6);
            }

            tlv* certTLV = get_tlv(serverHello, CERTIFICATE);
            if (!certTLV) {
                fprintf(stderr, "DEBUG (client): Missing certificate\n");
                free_tlv(serverHello);
                return;
            }

            tlv* dnsTLV = get_tlv(certTLV, DNS_NAME);
            tlv* serverPubKeyTLV = get_tlv(certTLV, PUBLIC_KEY);
            tlv* certSigTLV = get_tlv(certTLV, SIGNATURE);
            if (!dnsTLV || !serverPubKeyTLV || !certSigTLV) {
                fprintf(stderr, "DEBUG (client): Certificate missing fields\n");
                free_tlv(serverHello);
                return;
            }

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
                exit(1);
            }

            char dns_name[256];
            if (dnsTLV->length >= sizeof(dns_name)) {
                fprintf(stderr, "DEBUG (client): DNS name too long\n");
                free_tlv(serverHello);
                exit(2);
            }
            memcpy(dns_name, dnsTLV->val, dnsTLV->length);
            dns_name[dnsTLV->length] = '\0';
            if (strcmp(dns_name, g_host) != 0) {
                fprintf(stderr, "DEBUG (client): DNS name mismatch! Expected '%s', got '%s'\n", g_host, dns_name);
                free_tlv(serverHello);
                exit(2);
            }

            tlv* sigTLV = get_tlv(serverHello, HANDSHAKE_SIGNATURE);
            if (!sigTLV) {
                fprintf(stderr, "DEBUG (client): Missing signature\n");
                free_tlv(serverHello);
                return;
            }

            tlv* serverNonceTLV = get_tlv(serverHello, NONCE);
            tlv* serverEphemeralPubTLV = get_tlv(serverHello, PUBLIC_KEY);
            if (!serverNonceTLV || !serverEphemeralPubTLV) {
                fprintf(stderr, "DEBUG (client): Missing fields in Server Hello\n");
                free_tlv(serverHello);
                return;
            }

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

            load_peer_public_key(serverPubKeyTLV->val, serverPubKeyTLV->length);
            verify_result = verify(sigTLV->val, sigTLV->length, transcript, offset, ec_peer_public_key);
            if (verify_result != 1) {
                fprintf(stderr, "DEBUG (client): Server Hello signature verification failed!\n");
                free_tlv(serverHello);
                exit(3);
            }

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

            uint8_t transcript_digest[MAC_SIZE];
            hmac(transcript_digest, salt, client_hello_len + server_hello_len);
            free(salt);

            tlv* transcriptTLV = create_tlv(TRANSCRIPT);
            add_val(transcriptTLV, transcript_digest, MAC_SIZE);
            tlv* finishedTLV = create_tlv(FINISHED);
            add_tlv(finishedTLV, transcriptTLV);
            finished_len = serialize_tlv(finished_buf, finishedTLV);
            free_tlv(finishedTLV);
            free_tlv(serverHello);

            return; // FINISHED sent in input_sec
        } else if (client_state == CLIENT_STATE_DATA && handshake_complete) {
            // Receive and decrypt encrypted data from the server
            tlv* dataTLV = deserialize_tlv(buf, length);
            if (!dataTLV || dataTLV->type != DATA) {
                fprintf(stderr, "DEBUG (client): Expected DATA TLV, got %02x\n", dataTLV ? dataTLV->type : 0);
                output_io(buf, length); // Fall back
                free_tlv(dataTLV);
                return;
            }

            tlv* ivTLV = get_tlv(dataTLV, IV);
            tlv* cipherTLV = get_tlv(dataTLV, CIPHERTEXT);
            tlv* macTLV = get_tlv(dataTLV, MAC);
            if (!ivTLV || ivTLV->length != 16 || !cipherTLV || !macTLV || macTLV->length != 32) {
                fprintf(stderr, "DEBUG (client): Missing or invalid TLVs in DATA\n");
                free_tlv(dataTLV);
                exit(5);
            }

            uint8_t iv_buf[18];
            uint16_t iv_len = serialize_tlv(iv_buf, ivTLV);
            uint8_t cipher_buf[963];
            uint16_t cipher_len = serialize_tlv(cipher_buf, cipherTLV);
            uint8_t hmac_input[981];
            memcpy(hmac_input, iv_buf, iv_len);
            memcpy(hmac_input + iv_len, cipher_buf, cipher_len);
            size_t hmac_input_size = iv_len + cipher_len;

            uint8_t computed_mac[32];
            hmac(computed_mac, hmac_input, hmac_input_size);

            if (memcmp(macTLV->val, computed_mac, 32) != 0) {
                fprintf(stderr, "DEBUG (client): HMAC verification failed\n");
                free_tlv(dataTLV);
                exit(5);
            }

            uint8_t plaintext[960];
            size_t plaintext_size = decrypt_cipher(plaintext, cipherTLV->val, cipherTLV->length, ivTLV->val);

            write(STDOUT_FILENO, plaintext, plaintext_size);

            free_tlv(dataTLV);
            return;
        }
    }
    output_io(buf, length);
}