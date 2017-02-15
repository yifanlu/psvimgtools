/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "restore.h"
#include "utils.h"

int main(int argc, const char *argv[]) {
  args_t args1, args2;
  struct stat st;
  int fds[2];
  pid_t pid;
  int status;

  if (argc < 5) {
    fprintf(stderr, "usage: psvmd-decrypt -K key input.psvmd output\n");
    return 1;
  }

  if (pipe(fds) < 0) {
    perror("pipe");
    return 1;
  }

  args1.in = open(argv[3], O_RDONLY);
  if (args1.in < 0) {
    perror("input");
    return 1;
  }
  args1.out = fds[1];
  args2.in = fds[0];
  args2.out = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (args2.out < 0) {
    perror("output");
    return 1;
  }

  if (parse_key(argv[2], args1.key) < 0) {
    fprintf(stderr, "invalid key\n");
    return 1;
  }

  if ((pid = fork()) == 0) {
    close(args1.in);
    close(args1.out);
    decompress_thread(&args2);
    return 0;
  } else if (pid > 0) {
    close(args2.in);
    close(args2.out);
    decrypt_thread(&args1);
  } else {
    perror("fork");
    return 1;
  }

  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return 1;
  }

  if (!WIFEXITED(status)) {
    fprintf(stderr, "child process returned error\n");
    return 1;
  }

  fprintf(stderr, "all done.\n");

  return 0;
}
