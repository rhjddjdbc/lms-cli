#ifndef LMS_H
#define LMS_H
#include <stdint.h>
#include "lm_ots.h"

#define LMS_HEIGHT 10
#define LMS_LEAVES 1024

// RFC 8554 compliant signature size:
// LMS type (4) + LMOTS type (4) + q (4) + LM-OTS sig (4 + 32 + 34*32) + auth path (10*32)
#define SIG_BYTES (4 + 4 + 4 + (4 + N + P*N) + LMS_HEIGHT * N)   // = 1460 Bytes

int lms_keygen(const uint8_t I[16], uint8_t seed[32],
               uint8_t pub[20 + N],
               uint8_t tree[2*LMS_LEAVES][N]);

int lms_sign(const uint8_t I[16], uint32_t q, const uint8_t seed[N],
             const uint8_t tree[2*LMS_LEAVES][N],
             const uint8_t *msg, size_t msglen,
             uint8_t sig[SIG_BYTES]);

int lms_verify(const uint8_t pub[20 + N],
               const uint8_t *msg, size_t msglen,
               const uint8_t sig[SIG_BYTES]);

void lms_build_tree(const uint8_t I[16], uint8_t seed[32],
                    uint8_t tree[2*LMS_LEAVES][N]);

#endif
