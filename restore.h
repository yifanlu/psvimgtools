/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef RESTORE_H__
#define RESTORE_H__

typedef struct args {
  int in;
  int out;
  unsigned char key[32];
  const char *prefix;
} args_t;

void *decrypt_thread(void *pargs);
void *decompress_thread(void *pargs);
void *unpack_thread(void *pargs);

#endif
