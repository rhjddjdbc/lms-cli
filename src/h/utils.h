#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

void u32_to_bytes(uint32_t v, uint8_t *out);
uint32_t bytes_to_u32(const uint8_t *in);
void u16_to_bytes(uint16_t v, uint8_t *out);

int secure_random(uint8_t *buf, size_t len);

int read_file(const char *path, uint8_t **data, size_t *len);
int write_file(const char *path, const uint8_t *data, size_t len);

#endif
