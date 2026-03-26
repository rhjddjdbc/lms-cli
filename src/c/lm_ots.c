#include "lm_ots.h"
#include "sha256.h"
#include "utils.h"
#include <string.h>

static void derive_secret_i(const uint8_t seed[N], uint32_t q, uint16_t i, uint8_t out[N]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uint8_t tmp[6];
    u32_to_bytes(q, tmp);
    tmp[4] = i >> 8;
    tmp[5] = i & 0xff;
    sha256_update(&ctx, seed, N);
    sha256_update(&ctx, tmp, 6);
    sha256_final(&ctx, out);
}

static uint16_t lmots_checksum(const uint8_t *Q) {
    uint16_t cksm = 0;
    for (int i = 0; i < N; i++) {
        cksm += 255 - Q[i];
    }
    return cksm;
}

static uint8_t lmots_coef(const uint8_t *Qcksm, uint16_t i) {
    return Qcksm[i];
}

// RFC 8554 compliant chain function with D_ITER
void lmots_chain(uint8_t *out, const uint8_t *in, uint16_t start, uint16_t steps,
                 const uint8_t I[16], uint32_t q, uint16_t i) {
    uint8_t tmp[N];
    memcpy(tmp, in, N);
    for (uint16_t a = start; a < start + steps; a++) {
        SHA256_CTX ctx;
        sha256_init(&ctx);

        uint8_t pre[25]; // I(16) + q(4) + i(2) + a(1) + D_ITER(2)
        memcpy(pre, I, 16);
        u32_to_bytes(q, pre + 16);
        u16_to_bytes(i, pre + 20);
        pre[22] = (uint8_t)a;
        u16_to_bytes(D_ITER, pre + 23);

        sha256_update(&ctx, pre, 25);
        sha256_update(&ctx, tmp, N);
        sha256_final(&ctx, tmp);
    }
    memcpy(out, tmp, N);
}

int lmots_sign(const uint8_t I[16], uint32_t q, const uint8_t secret[N],
               const uint8_t *msg, size_t msglen, uint8_t sig[N + P*N]) {
    uint8_t C[N];
    if (secure_random(C, N) != 0) {
        return -1;
    }

    // Compute Q = H(I || u32str(q) || u16str(D_MESG) || C || msg)
    uint8_t Q[N];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uint8_t pre[22];
    memcpy(pre, I, 16);
    u32_to_bytes(q, pre + 16);
    u16_to_bytes(D_MESG, pre + 20);
    sha256_update(&ctx, pre, 22);
    sha256_update(&ctx, C, N);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, Q);

    uint16_t cksm = lmots_checksum(Q);
    uint8_t Qcksm[N + 2];
    memcpy(Qcksm, Q, N);
    u16_to_bytes(cksm, Qcksm + N);

    // Signature format: C || y[0] || ... || y[P-1]
    memcpy(sig, C, N);
    uint8_t *y = sig + N;

    for (uint16_t i = 0; i < P; i++) {
        uint8_t a = lmots_coef(Qcksm, i);
        uint8_t x_i[N];
        derive_secret_i(secret, q, i, x_i);
        lmots_chain(y + i * N, x_i, 0, a, I, q, i);
    }
    return 0;
}

int lmots_reconstruct_pub(const uint8_t I[16], uint32_t q,
                          const uint8_t *ots_sig,
                          const uint8_t *msg, size_t msglen,
                          uint8_t pubhash[N]) {

    const uint8_t *C = ots_sig;
    const uint8_t *y = ots_sig + N;

    // Recompute Q
    uint8_t Q[N];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uint8_t pre[22];
    memcpy(pre, I, 16);
    u32_to_bytes(q, pre + 16);
    u16_to_bytes(D_MESG, pre + 20);
    sha256_update(&ctx, pre, 22);
    sha256_update(&ctx, C, N);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, Q);

    uint16_t cksm = lmots_checksum(Q);
    uint8_t Qcksm[N + 2];
    memcpy(Qcksm, Q, N);
    u16_to_bytes(cksm, Qcksm + N);

    uint8_t z[P][N];
    for (uint16_t i = 0; i < P; i++) {
        uint8_t a = lmots_coef(Qcksm, i);
        lmots_chain(z[i], y + i * N, a, 255 - a, I, q, i);
    }

    // pubhash = H(I || u32(q) || u16(D_PBLC) || z[0]..z[P-1])
    sha256_init(&ctx);
    memcpy(pre, I, 16);
    u32_to_bytes(q, pre + 16);
    u16_to_bytes(D_PBLC, pre + 20);
    sha256_update(&ctx, pre, 22);
    for (int i = 0; i < P; i++) {
        sha256_update(&ctx, z[i], N);
    }
    sha256_final(&ctx, pubhash);

    return 0;
}
