/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <stdint.h>
#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif

#define AES_BLOCK_SIZE 16
#define SHA256_BLOCK_SIZE 32

#ifdef HAVE_GCRYPT
static inline void aes256_cbc_decrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  gcry_cipher_hd_t ctx;

  gcry_cipher_open(&ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  gcry_cipher_setkey(ctx, key, 32);
  gcry_cipher_setiv(ctx, iv, AES_BLOCK_SIZE);
  gcry_cipher_decrypt(ctx, buffer, blocks * AES_BLOCK_SIZE, NULL, 0);
  gcry_cipher_close(ctx);
}

static inline void aes256_cbc_encrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  gcry_cipher_hd_t ctx;

  gcry_cipher_open(&ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  gcry_cipher_setkey(ctx, key, 32);
  gcry_cipher_setiv(ctx, iv, AES_BLOCK_SIZE);
  gcry_cipher_encrypt(ctx, buffer, blocks * AES_BLOCK_SIZE, NULL, 0);
  gcry_cipher_close(ctx);
}
#else // HAVE_GCRYPT
#include "aes256.h"
static inline void aes256_cbc_decrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  aes256_context ctx;

  aes256_init(&ctx, key);
  for (int i = blocks-1; i >= 0; i--) {
    aes256_decrypt_ecb(&ctx, &buffer[i * AES_BLOCK_SIZE]);
    for (int j = 0; j < AES_BLOCK_SIZE; j++) {
      buffer[i*AES_BLOCK_SIZE + j] ^= (i == 0) ? iv[j] : buffer[(i-1)*AES_BLOCK_SIZE + j];
    }
  }
  aes256_done(&ctx);
}

static inline void aes256_cbc_encrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  aes256_context ctx;

  aes256_init(&ctx, key);
  for (int i = 0; i < blocks; i++) {
    for (int j = 0; j < AES_BLOCK_SIZE; j++) {
      buffer[i*AES_BLOCK_SIZE + j] ^= (i == 0) ? iv[j] : buffer[(i-1)*AES_BLOCK_SIZE + j];
    }
    aes256_encrypt_ecb(&ctx, &buffer[i * AES_BLOCK_SIZE]);
  }
  aes256_done(&ctx);
}
#endif // HAVE_GCRYPT

#ifdef HAVE_GCRYPT
#define SHA256_CTX gcry_md_hd_t
#define sha256_init(ctx) gcry_md_open(ctx, GCRY_MD_SHA256, 0)
#define sha256_update(ctx, data, len) gcry_md_write(*(ctx), data, len)
#define sha256_copy(ctx1, ctx2) gcry_md_copy(ctx1, *(ctx2))
#define sha256_final(ctx, hash) do { \
  memcpy(hash, gcry_md_read(*(ctx), 0), SHA256_BLOCK_SIZE); \
  gcry_md_close(*(ctx)); \
} while (0)
#else // HAVE_GCRYPT
#include "sha256.h"
#endif // HAVE_GCRYPT

#endif
