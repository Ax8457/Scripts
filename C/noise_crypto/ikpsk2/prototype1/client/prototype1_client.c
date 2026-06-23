// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

/*
	Libs
*/
#include "client.h"
#include <stdio.h>   
#include <stdint.h>  
#include <string.h>  
#include "noise_crypto.h"  

//launch server
int main(){
	//cipher text vars
	uint8_t encrypted_static_key[NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES];
	uint8_t encrypted_timestamp[NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES];
	//key var used for temp storing after dh computations
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	//create and complete peer structs
    	noise_peer p;
    	noise_keypair k1;
    	noise_keypair k2;
    	noise_handshake n_h;
    	noise_peer *client_peer = &p;
    	noise_keypair *n_static_k = &k1 ; 
    	noise_keypair *n_ephemeral_k = &k2;
    	client_peer->n_handshake = &n_h;
    	client_peer->n_handshake->state = HANDSHAKE_ZEROED;
    	ikpsk2_msg1 i_m1;
	ikpsk2_msg1 *ikpsk2_m1 = &i_m1;
    	//seed
    	sodium_hex2bin(client_peer->seed,crypto_box_SEEDBYTES,CLIENT_SEED,64,NULL,NULL, NULL);
    	//generate key pairs
    	generate_static_keys(n_static_k, client_peer); //cf crypto : seed = deterministic (<=> hardcoded keys)
    	
    	/*
    		/!\ TODO relocate ephemeral to have different ephemerals generated for each client
    	*/
    	generate_ephemeral_keys(n_ephemeral_k); //cf crypto : random keys => in RAM  (no seed)
    	client_peer->static_keys = n_static_k;
    	client_peer->ephemeral_keys = n_ephemeral_k;
    	//remote pubkey
	//store server pubkey in client struct
	sodium_base642bin(
        	client_peer->remote_public_key, 
        	sizeof(client_peer->remote_public_key),
        	SERVER_STATIC_PUBKEY, 
        	strlen(SERVER_STATIC_PUBKEY),
        	NULL, 
        	NULL, 
        	NULL, 
        	sodium_base64_VARIANT_ORIGINAL
        ); //Cf Ikpsk2 => K: client already know server pubkey
    	//psk
    	//psk
    	sodium_hex2bin(
    		client_peer->n_handshake->psk,
    		NOISE_SYMMETRIC_KEY_LEN,
    		PSK,
    		64,
    		NULL,
    		NULL, 
    		NULL);
	//open connection to server
	/*
		Handshake init: C0, H0, H1
		C0 = hash(handshake_name)  **arbitrary notation
		H0 = hash(C0,identifier_name)  **arbitrary notation
		H1 = hash(H0, Static responder Pubkey S_pub_i)
	*/
	ikpsk2_noise_init();
	printf("Init ok\n");
	
	//DEBUG
	printf("Chaining Key (C0): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", handshake_init_chaining_key[i]);
	}
	printf("\n");
	printf("Hash Transcript (H0): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", handshake_init_hash[i]);
	}
	printf("\n");
	//DEBUG
	
	//init handshake with dedicated function => H1
	init_handshake(client_peer->n_handshake->chaining_key, client_peer->n_handshake->hash_transcript,client_peer->remote_public_key);
	//DEBUG
	printf("Hash Transcript updated (H1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->hash_transcript[i]);
	}
	printf("\n");
	//DEBUG
	/*
		Message 1: e 
		C1 + H2
		e:
			C1 = hkdf(C0, Ephemeral pub initiator)
			H2 = hash(H1, Ephermeral pub initiator)
	*/
	message_e(client_peer->ephemeral_keys->public_key, client_peer->n_handshake->chaining_key, client_peer->n_handshake->hash_transcript);
	//DEBUG
	printf("Chaining key updated (C1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->chaining_key[i]);
	}
	printf("\n");
	printf("Hash Transcript updated (H2): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->hash_transcript[i]);
	}
	printf("\n");
	//DEBUG
	/*
		Message 1: es 
		C2 + k1
		es:
			C2 || K1 = hkdf(C1, dh(Ephemeral private initiator, Static Public responder)
	*/
	mix_dh(client_peer->n_handshake->chaining_key, key, client_peer->ephemeral_keys->private_key, client_peer->remote_public_key);
	//DEBUG
	printf("Chaining key updated (C2): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->chaining_key[i]);
	}
	printf("\n");
	printf("Key (K1): ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    		printf("%02x", key[i]);
	}
	printf("\n");
	//DEBUG
	
	/*
		Message1 : s
		s: 
			S pub encrypted 
			H3 = hash(H2, S_pub_encrypted)
	*/
	message_encrypt(encrypted_static_key, client_peer->static_keys->public_key, NOISE_PUBLIC_KEY_LEN, key, client_peer->n_handshake->hash_transcript);
	printf("Unencrypted pubkey (static): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->static_keys->public_key[i]);
	}
	printf("\n");
	printf("Encrypted pubkey (static): ");
	for (int i = 0; i < (NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES); i++) {
    		printf("%02x", encrypted_static_key[i]);
	}
	printf("\n");
	printf("Hash Transcript updated (H3): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->hash_transcript[i]);
	}
	printf("\n");
	
	/*
		Message1 : ss
		C3 + k2
		ss: 
			C3||K2 = hkdf(C2, dh(Static private initiator, static public responder)
	*/
	mix_dh(client_peer->n_handshake->chaining_key, key, client_peer->static_keys->private_key, client_peer->remote_public_key);
	//DEBUG
	printf("Chaining key updated (C3): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->chaining_key[i]);
	}
	printf("\n");
	printf("Key (K2): ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    		printf("%02x", key[i]);
	}
	printf("\n");
	//DEBUG
	
	/*
		Timestamp enc
		enc_ts = enc(k2, ts, H3)
	*/
	get_userspace_timestamp(client_peer->last_timestamp);
	message_encrypt(encrypted_timestamp, client_peer->last_timestamp, NOISE_TIMESTAMP_LEN, key, client_peer->n_handshake->hash_transcript);
	//DEBUG
	printf("Timestamp : ");
	for (int i = 0; i < NOISE_TIMESTAMP_LEN; i++) {
    		printf("%02x", client_peer->last_timestamp[i]);
	}
	printf("\n");
	printf("Encrypted timestamp : ");
	for (int i = 0; i < (NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES); i++) {
    		printf("%02x", encrypted_timestamp[i]);
	}
	printf("\n");
	printf("Hash Transcript updated (H4): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    		printf("%02x", client_peer->n_handshake->hash_transcript[i]);
	}
	printf("\n");
	//DEBUG
	
	/*
		Send message to server
	*/
	// complete msg1 struct using memcpy
	memcpy(ikpsk2_m1->ephemeral_public_key, client_peer->ephemeral_keys->public_key, NOISE_PUBLIC_KEY_LEN);
	memcpy(ikpsk2_m1->encrypted_static_key, encrypted_static_key, NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES);
	memcpy(ikpsk2_m1->encrypted_timestamp, encrypted_timestamp, NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES);
	
	//bind server through named pipes
	bind_server(ikpsk2_m1, client_peer);
    	return 0;
}
