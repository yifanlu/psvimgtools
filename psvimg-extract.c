/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "restore.h"
#include "utils.h"

int main(int argc, const char *argv[]) {
  args_t args1, args2;
  struct stat st;
  int fds[2];
  pthread_t t1, t2;

  if (argc < 5) {
    fprintf(stderr, "usage: psvimg-extract -K key input.psvimg outputdir\n");
    return 1;
  }

  if (pipe(fds) < 0) {
    perror("pipe");
    return 1;
  }

  args1.in = open(argv[3], O_RDONLY);
  if (args1.in < 0) {
    perror("open");
    return 1;
  }
  args1.out = fds[1];
  args2.in = fds[0];
  args2.out = 0;

  if (parse_key(argv[2], args1.key) < 0) {
    fprintf(stderr, "invalid key\n");
    return 1;
  }

  args2.prefix = argv[4];
  if (stat(args2.prefix, &st) < 0) {
    mkdir(args2.prefix, 0700);
  }

  pthread_create(&t1, NULL, decrypt_thread, &args1);
  pthread_create(&t2, NULL, unpack_thread, &args2);

  pthread_join(t1, NULL);
  pthread_join(t2, NULL);

  fprintf(stderr, "all done.\n");

  return 0;
}
