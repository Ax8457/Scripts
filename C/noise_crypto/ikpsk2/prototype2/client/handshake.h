#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "noise_crypto.h"
#include <stdint.h>

extern void load_conf( const char *filename, uint8_t local_priv[NOISE_PUBLIC_KEY_LEN], uint8_t remote_pub[NOISE_PUBLIC_KEY_LEN], uint8_t psk[NOISE_SYMMETRIC_KEY_LEN]);
extern void noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake);
extern void handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer);
extern void handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
extern void handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
extern void begin_session(struct noise_peer *peer);

#endif
