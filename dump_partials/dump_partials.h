/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef DUMP_PARTIALS_H__
#define DUMP_PARTIALS_H__

#define AES_BLOCK_SIZE 16

typedef struct {
    char key_seed[0x20];
    int key_size;
    int dmac5_cmd;
    void *output;
} args_t;

#endif
