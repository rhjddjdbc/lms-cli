#include "lms.h"
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

static void compute_ots_pub(const uint8_t I[16], uint32_t q,
                            const uint8_t seed[N], uint8_t K[N]) {
    uint8_t z[P][N];

    for (uint16_t i = 0; i < P; i++) {
        uint8_t x_i[N];
        derive_secret_i(seed, q, i, x_i);
        lmots_chain(z[i], x_i, 0, 255, I, q, i);
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t pre[22];
    memcpy(pre, I, 16);
    u32_to_bytes(q, pre + 16);
    u16_to_bytes(D_PBLC, pre + 20);

    sha256_update(&ctx, pre, 22);
    for (int i = 0; i < P; i++)
        sha256_update(&ctx, z[i], N);

    sha256_final(&ctx, K);
}

static void hash_leaf(const uint8_t I[16], uint32_t node,
                      const uint8_t K[N], uint8_t out[N]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t pre[16 + 4 + 2];
    memcpy(pre, I, 16);
    u32_to_bytes(node, pre + 16);
    u16_to_bytes(D_LEAF, pre + 20);

    sha256_update(&ctx, pre, sizeof(pre));
    sha256_update(&ctx, K, N);

    sha256_final(&ctx, out);
}

static void hash_internal(const uint8_t I[16], uint32_t node,
                          const uint8_t left[N], const uint8_t right[N],
                          uint8_t out[N]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t pre[16 + 4 + 2];
    memcpy(pre, I, 16);
    u32_to_bytes(node, pre + 16);
    u16_to_bytes(D_INTR, pre + 20);

    sha256_update(&ctx, pre, sizeof(pre));
    sha256_update(&ctx, left, N);
    sha256_update(&ctx, right, N);

    sha256_final(&ctx, out);
}

// ===== FIXED TREE =====
void lms_build_tree(const uint8_t I[16], uint8_t seed[32],
                    uint8_t tree[2*LMS_LEAVES][N]) {

    // Leaves
    for (int q = 0; q < LMS_LEAVES; q++) {
        uint8_t K[N];
        compute_ots_pub(I, (uint32_t)q, seed, K);

        uint32_t node = LMS_LEAVES + q;
        hash_leaf(I, node, K, tree[node]);
    }

    // Internal nodes
    for (int i = LMS_LEAVES - 1; i >= 1; i--) {
        hash_internal(I, i, tree[2*i], tree[2*i + 1], tree[i]);
    }
}

int lms_keygen(const uint8_t I[16], uint8_t seed[32],
               uint8_t pub[20 + N],
               uint8_t tree[2*LMS_LEAVES][N]) {
    lms_build_tree(I, seed, tree);

    u32_to_bytes(0x00000006, pub);
    memcpy(pub + 4, I, 16);
    memcpy(pub + 20, tree[1], N);

    return 0;
}

// Helper constant-time compare
static int constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;  // 0 only if equal
}

int lms_sign(const uint8_t I[16], uint32_t q, const uint8_t seed[N],
             const uint8_t tree[2*LMS_LEAVES][N],
             const uint8_t *msg, size_t msglen,
             uint8_t sig[SIG_BYTES]) {   // SIG_BYTES now 1456
    uint8_t ots[4 + N + P * N];
    if (lmots_sign(I, q, seed, msg, msglen, ots) != 0)
        return -1;

    // RFC format: LMS typecode || q || OTS_sig || auth path
    u32_to_bytes(0x00000006, sig);                  // LMS_SHA256_M32_H10
    u32_to_bytes(q, sig + 4);
    memcpy(sig + 8, ots, sizeof(ots));

    uint8_t *path = sig + 8 + sizeof(ots);
    int node = LMS_LEAVES + q;
    for (int i = 0; i < LMS_HEIGHT; i++) {
        int sibling = node ^ 1;
        memcpy(path + i * N, tree[sibling], N);
        node >>= 1;
    }
    return 0;
}

int lms_verify(const uint8_t pub[20 + N],
               const uint8_t *msg, size_t msglen,
               const uint8_t sig[SIG_BYTES]) {
    if (bytes_to_u32(sig) != 0x00000006) {  // must be LMS_SHA256_M32_H10
        return -1;
    }

    uint32_t q = bytes_to_u32(sig + 4);
    if (q >= LMS_LEAVES) return -1;

    const uint8_t *ots_sig = sig + 8;
    const uint8_t *path = sig + 8 + (4 + N + P * N);

    uint8_t I[16];
    memcpy(I, pub + 4, 16);

    uint8_t K_ots[N];
    if (lmots_reconstruct_pub(I, q, ots_sig, msg, msglen, K_ots) != 0)
        return -1;

    uint32_t node = LMS_LEAVES + q;
    uint8_t current[N];
    hash_leaf(I, node, K_ots, current);

    for (int i = 0; i < LMS_HEIGHT; i++) {
        uint8_t tmp[N];
        const uint8_t *sib = path + i * N;
        if (node % 2 == 0)
            hash_internal(I, node >> 1, current, sib, tmp);
        else
            hash_internal(I, node >> 1, sib, current, tmp);
        memcpy(current, tmp, N);
        node >>= 1;
    }

    // Constant-time compare root
    return (constant_time_memcmp(current, pub + 20, N) == 0) ? 0 : -1;
}
