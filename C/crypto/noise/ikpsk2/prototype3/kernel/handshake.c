// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/
#include "noise_crypto.h"



//INITIATOR -> handshake initiation creation 
void noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake)
{	
	//vars 
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	//init handshake between client and server
	/*
	*	H1 = hash(H0 || Static_pubkey_responder)
	*/

	init_handshake(handshake->chaining_key, handshake->hash_transcript, handshake->remote_static);
	
	/*
		e : C1 & H2
		C1 = hkdf1(C0,E_pub_i)
		H2 = hash(H1, E_pub_i)

	*/
	//generate ephemerals
	curve25519_generate_secret(handshake->ephemeral_private);
	curve25519_generate_public(m1->unencrypted_ephemeral, handshake->ephemeral_private);

	//hkdf & hash update
	message_e(m1->unencrypted_ephemeral,m1->unencrypted_ephemeral, handshake->chaining_key, handshake->hash_transcript);

	/*
		es: C2 & k1
		C2 || k1 = hkdf2(C1, dh(E_priv_i,S_pub_r))
	*/
	mix_dh(handshake->chaining_key, key , handshake->ephemeral_private, handshake->remote_static);
	
	/*
		s: timestamps encrypt & H3
		S pub encrypted = aenc(k1,0,S_pub_i,H2)
		H3 = hash(H2, S_pub_encrypted)
	*/
	message_encrypt(m1->encrypted_static, handshake->static_identity->static_public, NOISE_PUBLIC_KEY_LEN ,key, handshake->hash_transcript);

	/*
		ss: C3 & K2
		C3 || k2 = hkdf2(C2, dh(S_priv_i, S_pub_r))
		/!\ in the future use pre computed static static instead
	*/
	mix_dh(handshake->chaining_key, key, handshake->static_identity->static_private, handshake->remote_static);

	/*
		encrypte ts & H4
	*/
	tai64n_now(timestamp);
	message_encrypt(m1->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key, handshake->hash_transcript);

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

	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 s[NOISE_PUBLIC_KEY_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	
	/*
		H1
	*/
	init_handshake(chaining_key, hash_transcript, peer->handshake.static_identity->static_public);

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
	message_decrypt(s, m1->encrypted_static, NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key, hash_transcript);

	// part missing => look up in hash table in multiple client, for the moment -> single client
	/*
		ss : C3 + K2
	*/
	mix_dh(chaining_key,key,peer->handshake.static_identity->static_private, s);

	/*
		t: dec timestamp + h4
	*/
	message_decrypt(t, m1->encrypted_timestamp, NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN,key,hash_transcript);

	/*
		Update peer 
	*/
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->remote_static, s, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
    memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
    memcpy(handshake->hash_transcript, hash_transcript, NOISE_HASH_LEN);

	handshake->state = HANDSHAKE_CONSUMED_INITIATION;

}	

void handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	
	/*
		e: generate ephemerals + C4 & H5
	*/
	curve25519_generate_secret(peer->handshake.ephemeral_private);
	curve25519_generate_public(m2->ephemeral_public_key, peer->handshake.ephemeral_private);

	message_e(m2->ephemeral_public_key, m2->ephemeral_public_key, peer->handshake.chaining_key, peer->handshake.hash_transcript);

	/*
		ee : C5
	*/

	message_ee(peer->handshake.remote_ephemeral, peer->handshake.ephemeral_private,peer->handshake.chaining_key);

	/*
		se : C6
	*/
	message_se(peer->handshake.ephemeral_private, peer->handshake.remote_static,peer->handshake.chaining_key);

	/*
		psk
	*/
	mix_psk(peer->handshake.psk, key, peer->handshake.chaining_key, peer->handshake.hash_transcript);

	message_encrypt(m2->encrypted_empty, (u8 *)"", 0, key, peer->handshake.hash_transcript);

	//update state
	peer->handshake.state = HANDSHAKE_CREATED_RESPONSE;

}

void handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	struct noise_handshake *handshake = &peer->handshake; //for the moment no index table
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 empty[0];

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
	/*
		ee : C5
	*/
	message_ee(e, ephemeral_private, chaining_key);

	/*
		se: C6
	*/
	message_se(handshake->static_identity->static_private, e, chaining_key);

	/*
		psk : C7, pi k3 & H6 + H7
	*/
	mix_psk(preshared_key,key,chaining_key,hash_transcript);

	/*
		decrypt empty + H7
	*/
	message_decrypt(empty,m2->encrypted_empty,NOISE_AUTHTAG_LEN,key,hash_transcript);

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
	peer->symmetric_keys.i_am_the_initiator = peer->handshake.state == HANDSHAKE_CONSUMED_RESPONSE;
	if(peer->symmetric_keys.i_am_the_initiator){
		derive_keys(peer->symmetric_keys.sending_key, peer->symmetric_keys.receiving_key, peer->handshake.chaining_key);
	}
	else {
		derive_keys(peer->symmetric_keys.receiving_key, peer->symmetric_keys.sending_key, peer->handshake.chaining_key);
	}

}

EXPORT_SYMBOL(noise_handshake_create_initiation);
EXPORT_SYMBOL(handshake_consume_initiation);
EXPORT_SYMBOL(handshake_create_response);
EXPORT_SYMBOL(handshake_consume_response);
EXPORT_SYMBOL(begin_session);