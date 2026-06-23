// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "noise_crypto.h"

void load_conf(const char *filename, uint8_t local_priv[NOISE_PUBLIC_KEY_LEN], uint8_t remote_pub[NOISE_PUBLIC_KEY_LEN], uint8_t psk[NOISE_SYMMETRIC_KEY_LEN]) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("[x] failed openning file");
        return;
    }
	printf("conf file opened.\n");
    char line[256], key[64], val[128];
    size_t len;

    while (fgets(line, sizeof(line), fp)) {
<<<<<<< HEAD

        if (sscanf(line, " %63[^= ] = %127s", key, val) == 2) {
            
=======
        if (sscanf(line, " %63[^= ] = %127s", key, val) == 2) {
>>>>>>> 691af0440759cbd1e739365527da34d510a65368
            val[strcspn(val, "\r\n")] = 0;

            if (strcasecmp(key, "PrivateKey") == 0) {
                if (sodium_base642bin(local_priv, NOISE_PUBLIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0) {
                    sodium_base642bin(local_priv, NOISE_PUBLIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL);
                }
                printf("privkey loaded.\n");
            }
            else if (strcasecmp(key, "PublicKey") == 0) {
                if (sodium_base642bin(remote_pub, NOISE_PUBLIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0) {
                    sodium_base642bin(remote_pub, NOISE_PUBLIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL);
                }
                printf("remote pubkey loaded.\n");
            }
            else if (strcasecmp(key, "PresharedKey") == 0) {
                if (sodium_base642bin(psk, NOISE_SYMMETRIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0) {
                    sodium_base642bin(psk, NOISE_SYMMETRIC_KEY_LEN, val, strlen(val), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL);
                }
                printf("psk loaded.\n");
            }
        }
    }
    fclose(fp);
}

//INITIATOR -> handshake initiation creation 
void noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake)
{	
	//vars 
	uint8_t timestamp[NOISE_TIMESTAMP_LEN];
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	//init handshake between client and server
	/*
	*	H1 = hash(H0 || Static_pubkey_responder)
	*/

	init_handshake(handshake->chaining_key, handshake->hash_transcript, handshake->remote_static);
	printf("[DEBUG] Hash transcript updated (H1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->hash_transcript[i]);
	}
	printf("\n");
	
	/*
		e : C1 & H2
		C1 = hkdf1(C0,E_pub_i)
		H2 = hash(H1, E_pub_i)

	*/
	//generate ephemeral
	generate_ephemeral_secret(handshake->ephemeral_private);
	generate_public(m1->unencrypted_ephemeral, handshake->ephemeral_private);
	//hkdf & hash update
	message_e(m1->unencrypted_ephemeral,m1->unencrypted_ephemeral, handshake->chaining_key, handshake->hash_transcript);
	
	printf("[DEBUG] Chaining key updated (C1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->chaining_key[i]);
	}
	printf("\n");
	printf("[DEBUG] Hash transcript updated (H2): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->hash_transcript[i]);
	}
	printf("\n");

	/*
		es: C2 & k1
		C2 || k1 = hkdf2(C1, dh(E_priv_i,S_pub_r))
	*/
	mix_dh(handshake->chaining_key, key , handshake->ephemeral_private, handshake->remote_static);

	printf("[DEBUG] Chaining key updated (C2): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->chaining_key[i]);
	}
	printf("\n");
	
	/*
		s: timestamps encrypt & H3
		S pub encrypted = aenc(k1,0,S_pub_i,H2)
		H3 = hash(H2, S_pub_encrypted)
	*/
	message_encrypt(m1->encrypted_static, handshake->static_identity->static_public, NOISE_PUBLIC_KEY_LEN ,key, handshake->hash_transcript);
	
	printf("[DEBUG] Hash transcript updated (H3): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] Static pubkey encrypted (S Pub enc): ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES; i++) {
    	printf("%02x", m1->encrypted_static[i]);
	}
	printf("\n");

	/*
		ss: C3 & K2
		C3 || k2 = hkdf2(C2, dh(S_priv_i, S_pub_r))
		/!\ in the future use pre computed static static instead
	*/
	mix_dh(handshake->chaining_key, key, handshake->static_identity->static_private, handshake->remote_static);
	printf("[DEBUG] Chaining key updated (C3): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->chaining_key[i]);
	}
	printf("\n");

	/*
		encrypte ts & H4
	*/
	get_userspace_timestamp(timestamp);
	message_encrypt(m1->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key, handshake->hash_transcript);

	printf("[DEBUG] Hash transcript updated (H4): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", handshake->hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] TimeStamp encrypted (TS enc): ");
	for (int i = 0; i < NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES; i++) {
    	printf("%02x", m1->encrypted_timestamp[i]);
	}
	printf("\n");

	//update state
	/*
		Temp: outsourced in client main function	
	*/
	//handshake->state = HANDSHAKE_CREATED_INITIATION;
}



void handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer)
{
	//for the moment single client model
	struct noise_handshake *handshake = &peer->handshake;

	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t hash_transcript[NOISE_HASH_LEN];
	uint8_t s[NOISE_PUBLIC_KEY_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	uint8_t t[NOISE_TIMESTAMP_LEN];
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	
	//debug 	
	printf("[DEBUG] Received message: \n");
	printf("[DEBUG] TimeStamp encrypted (TS enc): ");
	for (int i = 0; i < NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES; i++) {
    	printf("%02x", m1->encrypted_timestamp[i]);
	}
	printf("\n");
	printf("[DEBUG] Static pubkey encrypted (S Pub enc): ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES; i++) {
    	printf("%02x", m1->encrypted_static[i]);
	}
	printf("\n");
	
	/*
		H1
	*/

	printf("[DEBUG] Static pubkey: ");
	for (int i = 0; i < NOISE_PUBLIC_KEY_LEN ; i++) {
    	printf("%02x", peer->handshake.static_identity->static_public[i]);
	}
	printf("\n");
	init_handshake(chaining_key, hash_transcript, peer->handshake.static_identity->static_public);
	printf("[DEBUG] Hash transcript updated (H1): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", hash_transcript[i]);
	}
	printf("\n");

	/*
		e : C1 & H2
	*/
	message_e(e,m1->unencrypted_ephemeral, chaining_key, hash_transcript );

	/*
		es: C2 & K1
	*/
	mix_dh(chaining_key, key, peer->handshake.static_identity->static_private,e);

	/*
		dec S_pub_i & H3
	*/
	message_decrypt(s, m1->encrypted_static, NOISE_PUBLIC_KEY_LEN + crypto_aead_chacha20poly1305_ABYTES, key, hash_transcript);

	// part missing => look up in hash table in multiple client, for the moment -> single client
	/*
		ss : C3 + K2
	*/
	mix_dh(chaining_key,key,peer->handshake.static_identity->static_private, s);

	/*
		t: dec timestamp + h4
	*/
	message_decrypt(t, m1->encrypted_timestamp, NOISE_TIMESTAMP_LEN + crypto_aead_chacha20poly1305_ABYTES,key,hash_transcript);

	/*
		Update peer 
	*/
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->remote_static, s, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
    memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
    memcpy(handshake->hash_transcript, hash_transcript, NOISE_HASH_LEN);

	handshake->state = HANDSHAKE_CONSUMED_INITIATION;

	printf("[DEBUG] Hash transcript updated (H4): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] Chaining key updated (C3): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");


}	

void handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	
	/*
		e: generate ephemerals + C4 & H5
	*/
	generate_ephemeral_secret(peer->handshake.ephemeral_private);
	generate_public(m2->ephemeral_public_key, peer->handshake.ephemeral_private);

	message_e(m2->ephemeral_public_key, m2->ephemeral_public_key, peer->handshake.chaining_key, peer->handshake.hash_transcript);

	printf("[DEBUG] Hash transcript updated (H5): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] Chaining key updated (C4): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.chaining_key[i]);
	}
	printf("\n");

	/*
		ee : C5
	*/

	message_ee(peer->handshake.remote_ephemeral, peer->handshake.ephemeral_private,peer->handshake.chaining_key);
	printf("[DEBUG] Chaining key updated (C5): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.chaining_key[i]);
	}
	printf("\n");

	/*
		se : C6
	*/
	message_se(peer->handshake.ephemeral_private, peer->handshake.remote_static,peer->handshake.chaining_key);
	printf("[DEBUG] Chaining key updated (C6): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.chaining_key[i]);
	}
	printf("\n");

	/*
		psk
	*/
	mix_psk(peer->handshake.psk, key, peer->handshake.chaining_key, peer->handshake.hash_transcript);
	printf("[DEBUG] Chaining key updated (C7): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.chaining_key[i]);
	}
	printf("\n");

	printf("[DEBUG] Hash transcript updated (H6): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.hash_transcript[i]);
	}
	printf("\n");

	message_encrypt(m2->encrypted_empty, (uint8_t *)"", 0, key, peer->handshake.hash_transcript);

	printf("[DEBUG] Hash transcript updated (H7): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.hash_transcript[i]);
	}
	printf("\n");

	//update state
	peer->handshake.state = HANDSHAKE_CREATED_RESPONSE;

}

void handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	struct noise_handshake *handshake = &peer->handshake; //for the moment no index table
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t hash_transcript[NOISE_HASH_LEN];
	uint8_t chaining_key[NOISE_HASH_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t empty[0];

	/*
		Complete handshake temp
	*/
	memcpy(hash_transcript, handshake->hash_transcript, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	memcpy(preshared_key, handshake->psk, NOISE_SYMMETRIC_KEY_LEN);

	/*
		e : C4 + H5
	*/
	message_e(e,m2->ephemeral_public_key, chaining_key, hash_transcript);
	printf("[DEBUG] Hash transcript updated (H5): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] Chaining key updated (C4): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");
	/*
		ee : C5
	*/
	message_ee(e, ephemeral_private, chaining_key);
	printf("[DEBUG] Chaining key updated (C5): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");

	/*
		se: C6
	*/
	message_se(handshake->static_identity->static_private, e, chaining_key);
	printf("[DEBUG] Chaining key updated (C6): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");

	/*
		psk : C7, pi k3 & H6 + H7
	*/
	mix_psk(preshared_key,key,chaining_key,hash_transcript);
	printf("[DEBUG] Chaining key updated (C7): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");
	printf("[DEBUG] Hash transcript updated (H6): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", peer->handshake.hash_transcript[i]);
	}
	printf("\n");

	/*
		decrypt empty + H7
	*/
	message_decrypt(empty,m2->encrypted_empty,crypto_aead_chacha20poly1305_ABYTES,key,hash_transcript);

	printf("[DEBUG] Hash transcript updated (H7): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", hash_transcript[i]);
	}
	printf("\n");
	printf("[DEBUG] Chaining key updated (C7): ");
	for (int i = 0; i < NOISE_HASH_LEN; i++) {
    	printf("%02x", chaining_key[i]);
	}
	printf("\n");

	/*
		copy everything to peer
	*/
	memcpy(handshake->hash_transcript, hash_transcript, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	
	//update state 
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
}

/*
	Derive keys and begin session
*/
void begin_session(struct noise_peer *peer)
{
	derive_keys(peer->symmetric_keys.receiving_key, peer->symmetric_keys.sending_key, peer->handshake.chaining_key);
	printf("[DEBUG] Receiving key: ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    	printf("%02x", peer->symmetric_keys.receiving_key[i]);
	}
	printf("\n");
	printf("[DEBUG] Sending key: ");
	for (int i = 0; i < NOISE_SYMMETRIC_KEY_LEN; i++) {
    	printf("%02x", peer->symmetric_keys.sending_key[i]);
	}
	printf("\n");
}

