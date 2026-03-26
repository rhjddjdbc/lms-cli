#ifndef LM_OTS_H
#define LM_OTS_H
#include <stdint.h>
#include <stddef.h>

#define N 32
#define W 8
#define P 34

#define D_PBLC 0x8080
#define D_MESG 0x8181
#define D_ITER 0x8282
#define D_LEAF 0x8283
#define D_INTR 0x8383


int lmots_sign(const uint8_t I[16], uint32_t q, const uint8_t secret[N],
               const uint8_t *msg, size_t msglen, uint8_t sig[N + P*N]);

int lmots_reconstruct_pub(const uint8_t I[16], uint32_t q,
                          const uint8_t *ots_sig,  
                          const uint8_t *msg, size_t msglen,
                          uint8_t pubhash[N]);

void lmots_chain(uint8_t *out, const uint8_t *in, uint16_t start, uint16_t steps,
                 const uint8_t I[16], uint32_t q, uint16_t i);

#endif
