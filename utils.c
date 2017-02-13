/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t read_block(int fd, void *buf, size_t nbyte) {
  ssize_t rd;
  size_t total;
  total = 0;
  while ((rd = read(fd, buf, nbyte)) > 0) {
    nbyte -= rd;
    buf = (char *)buf + rd;
    total += rd;
  }
  if (rd < 0) {
    return rd;
  } else {
    return total;
  }
}

ssize_t write_block(int fd, const void *buf, size_t nbyte) {
  ssize_t wr;
  size_t total;
  total = 0;
  while ((wr = write(fd, buf, nbyte)) > 0) {
    nbyte -= wr;
    buf = (char *)buf + wr;
    total += wr;
  }
  if (wr < 0) {
    return wr;
  } else {
    return total;
  }
}

int parse_key(const char *ascii, uint8_t key[0x20]) {
  int i;
  for (i = 0; i < 0x20; i++) {
    char byte[3];
    memcpy(byte, &ascii[2*i], 2);
    byte[2] = '\0';
    key[i] = strtol(byte, NULL, 16);
    if (key[i] == 0 && !(byte[0] == '0' && byte[1] == '0')) {
      return -1;
    }
  }
  if (ascii[2*i] != '\0') {
    return -1;
  } else {
    return 0;
  }
}
