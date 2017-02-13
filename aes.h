/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef AES_H__
#define AES_H__

#include <stdint.h>
#include "aes256.h"

#define AES_BLOCK_SIZE 16

static inline void sw_aes256_cbc_decrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
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

static inline void sw_aes256_cbc_encrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
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

#ifdef HAS_AESNI
extern int check_for_aes_instructions();
extern void intel_AES_dec256_CBC(uint8_t *cipherText,uint8_t *plainText,uint8_t *key,size_t numBlocks,uint8_t *iv);
extern void intel_AES_enc256_CBC(uint8_t *cipherText,uint8_t *plainText,uint8_t *key,size_t numBlocks,uint8_t *iv);
static inline void aes256_cbc_decrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  if (check_for_aes_instructions()) {
    intel_AES_dec256_CBC(buffer, buffer, key, blocks, iv);
  } else {
    sw_aes256_cbc_decrypt(buffer, key, iv, blocks);
  }
}

static inline void aes256_cbc_encrypt(uint8_t *buffer, uint8_t *key, uint8_t *iv, size_t blocks) {
  if (check_for_aes_instructions()) {
    intel_AES_enc256_CBC(buffer, buffer, key, blocks, iv);
  } else {
    sw_aes256_cbc_encrypt(buffer, key, iv, blocks);
  }
}
#else
#define aes256_cbc_decrypt sw_aes256_cbc_decrypt
#define aes256_cbc_encrypt sw_aes256_cbc_encrypt
#endif

#endif
