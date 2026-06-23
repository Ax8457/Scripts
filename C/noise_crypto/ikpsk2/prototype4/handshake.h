#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "noise_crypto.h"

void load_conf(const char *filename, u8 local_priv[NOISE_PUBLIC_KEY_LEN], u8 remote_pub[NOISE_PUBLIC_KEY_LEN], u8 psk[NOISE_SYMMETRIC_KEY_LEN]);
void noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake);
void handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer);
void handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
void handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
void begin_session(struct noise_peer *peer);

#endif
