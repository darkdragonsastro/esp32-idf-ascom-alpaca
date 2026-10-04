// Host stand-in for mbedtls/md5.h, for the native tests only. A plain
// RFC 1321 MD5 (test/test_alpaca_api/md5.cpp), so UniqueIDs match the device.
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct
{
  uint32_t state[4];
  uint64_t length;
  unsigned char buffer[64];
} mbedtls_md5_context;

void mbedtls_md5_init(mbedtls_md5_context *ctx);
void mbedtls_md5_free(mbedtls_md5_context *ctx);
int mbedtls_md5_starts(mbedtls_md5_context *ctx);
int mbedtls_md5_update(mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen);
int mbedtls_md5_finish(mbedtls_md5_context *ctx, unsigned char output[16]);
