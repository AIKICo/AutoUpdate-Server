#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buffer[64];
} MD5_CTX;

void md5_init(MD5_CTX *context);
void md5_update(MD5_CTX *context, const uint8_t *input, size_t inputLen);
void md5_final(MD5_CTX *context, uint8_t digest[16]);
int md5_file(const char *path, char output_hex[33]);

#endif /* MD5_H */
