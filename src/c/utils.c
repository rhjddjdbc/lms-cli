#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/random.h>   // getrandom()

void u32_to_bytes(uint32_t v, uint8_t *out) {
    out[0] = (v >> 24) & 0xff;
    out[1] = (v >> 16) & 0xff;
    out[2] = (v >> 8) & 0xff;
    out[3] = v & 0xff;
}

uint32_t bytes_to_u32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

void u16_to_bytes(uint16_t v, uint8_t *out) {
    out[0] = (v >> 8) & 0xff;
    out[1] = v & 0xff;
}

int secure_random(uint8_t *buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t r = getrandom(buf + total, len - total, 0);
        if (r < 0) {
            return -1; // FAIL HARD
        }
        total += r;
    }
    return 0;
}

int read_file(const char *path, uint8_t **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = malloc(*len);
    if (!*data) { fclose(f); return -1; }
    if (fread(*data, 1, *len, f) != *len) { fclose(f); free(*data); return -1; }
    fclose(f);
    return 0;
}

int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}
