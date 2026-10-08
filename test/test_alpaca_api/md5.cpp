// RFC 1321 MD5 behind the mbedtls_md5_* API that api.cpp calls.

#include <math.h>
#include <mbedtls/md5.h>
#include <string.h>

static const int SHIFT[64] = {
  7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
  4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
};

static uint32_t rotate_left(uint32_t x, int c)
{
  return (x << c) | (x >> (32 - c));
}

static void transform(uint32_t state[4], const unsigned char block[64])
{
  uint32_t m[16];
  for (int i = 0; i < 16; i++)
  {
    m[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) | ((uint32_t)block[i * 4 + 2] << 16) |
           ((uint32_t)block[i * 4 + 3] << 24);
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  for (int i = 0; i < 64; i++)
  {
    uint32_t f;
    int g;
    if (i < 16)
    {
      f = (b & c) | (~b & d);
      g = i;
    }
    else if (i < 32)
    {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    }
    else if (i < 48)
    {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    }
    else
    {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    // RFC 1321 table: K[i] = floor(|sin(i + 1)| * 2^32).
    uint32_t k = (uint32_t)(fabs(sin(i + 1)) * 4294967296.0);
    f = f + a + k + m[g];
    a = d;
    d = c;
    c = b;
    b = b + rotate_left(f, SHIFT[i]);
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void mbedtls_md5_init(mbedtls_md5_context *ctx)
{
  memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_md5_free(mbedtls_md5_context *ctx)
{
  memset(ctx, 0, sizeof(*ctx));
}

int mbedtls_md5_starts(mbedtls_md5_context *ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->length = 0;
  return 0;
}

int mbedtls_md5_update(mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen)
{
  for (size_t i = 0; i < ilen; i++)
  {
    ctx->buffer[ctx->length % 64] = input[i];
    ctx->length++;
    if (ctx->length % 64 == 0)
    {
      transform(ctx->state, ctx->buffer);
    }
  }
  return 0;
}

int mbedtls_md5_finish(mbedtls_md5_context *ctx, unsigned char output[16])
{
  uint64_t bit_length = ctx->length * 8;

  const unsigned char pad = 0x80;
  mbedtls_md5_update(ctx, &pad, 1);
  const unsigned char zero = 0;
  while (ctx->length % 64 != 56)
  {
    mbedtls_md5_update(ctx, &zero, 1);
  }
  for (int i = 0; i < 8; i++)
  {
    unsigned char byte = (unsigned char)(bit_length >> (8 * i));
    mbedtls_md5_update(ctx, &byte, 1);
  }

  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < 4; j++)
    {
      output[i * 4 + j] = (unsigned char)(ctx->state[i] >> (8 * j));
    }
  }
  return 0;
}
