#include "bundle.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int bundle_write(const char *filename, const LMS_Bundle *b) {
    FILE *f = fopen(filename, "wb");
    if (!f) return -1;

    fwrite(BUNDLE_MAGIC, 1, BUNDLE_MAGIC_LEN, f);
    uint8_t version[4] = {0,0,0,2};          
    fwrite(version, 1, 4, f);

    fwrite(b->I, 1, 16, f);
    uint8_t qbytes[4]; u32_to_bytes(b->next_q, qbytes);
    fwrite(qbytes, 1, 4, f);
    fwrite(b->pub, 1, 20 + N, f);

    fwrite(&b->has_seed, 1, 1, f);
    if (b->has_seed) fwrite(b->seed, 1, 32, f);

    fwrite(&b->has_tree, 1, 1, f);            
    if (b->has_tree) fwrite(b->tree, 1, 2*LMS_LEAVES*N, f);

    fwrite(&b->has_last_sig, 1, 1, f);
    if (b->has_last_sig) fwrite(b->last_sig, 1, SIG_BYTES, f);

    fclose(f);
    return 0;
}

int bundle_read(const char *filename, LMS_Bundle *b) {
    uint8_t *data = NULL;
    size_t len;
    if (read_file(filename, &data, &len) != 0) return -1;

    size_t pos = 0;
    if (memcmp(data + pos, BUNDLE_MAGIC, BUNDLE_MAGIC_LEN) != 0) goto error;
    pos += BUNDLE_MAGIC_LEN + 4; 

    memcpy(b->I, data + pos, 16); pos += 16;
    b->next_q = bytes_to_u32(data + pos); pos += 4;
    memcpy(b->pub, data + pos, 20 + N); pos += 20 + N;

    b->has_seed = data[pos++]; 
    if (b->has_seed) { memcpy(b->seed, data + pos, 32); pos += 32; }

    b->has_tree = data[pos++];                   
    if (b->has_tree) { memcpy(b->tree, data + pos, 2*LMS_LEAVES*N); pos += 2*LMS_LEAVES*N; }

    b->has_last_sig = data[pos++];
    if (b->has_last_sig) memcpy(b->last_sig, data + pos, SIG_BYTES);

    free(data);
    return 0;
error:
    free(data);
    return -3;
}
