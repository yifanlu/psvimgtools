/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef UTILS_H__
#define UTILS_H__

#include <stdint.h>

ssize_t read_block(int fd, void *buf, size_t nbyte);
ssize_t write_block(int fd, const void *buf, size_t nbyte);
int parse_key(const char *ascii, uint8_t key[0x20]);

#endif
