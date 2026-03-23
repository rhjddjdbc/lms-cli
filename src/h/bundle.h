#ifndef BUNDLE_H
#define BUNDLE_H

#include <stdint.h>
#include "lm_ots.h"
#include "lms.h"

#define BUNDLE_MAGIC "LMSB2026"
#define BUNDLE_MAGIC_LEN 8

typedef struct {
    uint8_t I[16];
    uint32_t next_q;
    uint8_t pub[20 + N];
    uint8_t has_seed;
    uint8_t seed[32];
    uint8_t has_tree;                   
    uint8_t tree[2*LMS_LEAVES][N];      
    uint8_t has_last_sig;
    uint8_t last_sig[SIG_BYTES];
} LMS_Bundle;

int bundle_write(const char *filename, const LMS_Bundle *b);
int bundle_read(const char *filename, LMS_Bundle *b);

#endif
