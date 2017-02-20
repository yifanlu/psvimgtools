/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "crypto.h"
#include "utils.h"
#ifdef __linux__
#include <sched.h>
#endif

#ifndef HAVE_GCRYPT
#error "libgcrypt is required for psvimg-keyfind!"
#else
#include <gcrypt.h>
#endif

typedef struct {
  uint32_t found;
  uint32_t at;
} status_t;

#define PBSTR "============================================================"
#define PBWIDTH 50

#define KEY_LEN (32)
#define PROGRESS_UPDATE (0x10000)

static void print_progress(uint32_t total) {
  double percent;
  int lpad, rpad;
  percent = total * 1.0 / 0x100000000LL;
  lpad = (int) (percent * PBWIDTH);
  rpad = PBWIDTH - lpad;
  printf("\r%3d%% [%.*s%*s] (left: 0x%08x)", (int)(percent * 100), lpad, PBSTR, rpad, "", ~total);
  fflush(stdout);
}

static void print_key(uint32_t guess[KEY_LEN/sizeof(uint32_t)], int knownlen) {
  uint8_t *key = (uint8_t *)guess;
  for (int i = 0; i < KEY_LEN; i++) {
    if (i < knownlen) {
      printf("%02X", key[i]);
    } else {
      printf("**");
    }
  }
  printf("\n");
}

int find_key(int fd, uint32_t guess[KEY_LEN/sizeof(uint32_t)], int idx, uint8_t partial[AES_BLOCK_SIZE], uint32_t start, uint32_t end) {
  gcry_cipher_hd_t ctx;
  uint8_t zeros[AES_BLOCK_SIZE];
  uint8_t tmp[AES_BLOCK_SIZE];
  status_t st;

  memset(guess, 0, KEY_LEN);
  memset(zeros, 0, sizeof(zeros));
  st.found = 0;
  gcry_cipher_open(&ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
  for (st.at = start; st.at < end; st.at++) {
    guess[idx] = st.at;
    gcry_cipher_setkey(ctx, guess, KEY_LEN);
    gcry_cipher_encrypt(ctx, tmp, sizeof(tmp), zeros, sizeof(zeros));
    if (memcmp(tmp, partial, AES_BLOCK_SIZE) == 0) {
      st.found = 1;
      goto end;
    }
    if ((st.at % PROGRESS_UPDATE) == 0) {
      if (write_block(fd, &st, sizeof(st)) < 0) {
        goto end;
      }
    }
  }
  // last one
  guess[idx] = st.at;
  gcry_cipher_setkey(ctx, guess, KEY_LEN);
  gcry_cipher_encrypt(ctx, tmp, sizeof(tmp), zeros, sizeof(zeros));
  if (memcmp(tmp, partial, AES_BLOCK_SIZE) == 0) {
    st.found = 1;
  }
end:
  write_block(fd, &st, sizeof(st));
  close(fd);
  gcry_cipher_close(ctx);
  return st.found;
}

int dispatch_jobs(int num_jobs, uint32_t guess[KEY_LEN/sizeof(uint32_t)], int idx, uint8_t partial[AES_BLOCK_SIZE]) {
  struct pollfd fds[num_jobs];
  pid_t pids[num_jobs];
  uint32_t part_size;
  uint32_t at[num_jobs];

  part_size = 0x100000000LL / num_jobs;
  fprintf(stderr, "dispatching %d jobs with 0x%X tries per job.\n", num_jobs, part_size == 0 ? 0xFFFFFFFF : part_size);
  for (int i = 0; i < num_jobs; i++) {
    int tmp[2];
    if (pipe(tmp) < 0) {
      perror("pipe");
      return 0;
    }
    fds[i].fd = tmp[0];
    fds[i].events = POLLIN;
    at[i] = i * part_size;
    if ((pids[i] = fork()) < 0) {
      perror("fork");
      return 0;
    } else if (pids[i] == 0) {
      uint32_t end;
      close(tmp[0]);
      end = (i+1)*part_size-1;
      if (end < at[i]) {
        end = 0xFFFFFFFF;
      }
#ifdef __linux__
      cpu_set_t cpu;
      CPU_ZERO(&cpu);
      CPU_SET(i, &cpu);
      sched_setaffinity(0, sizeof(cpu), &cpu);
#endif
      exit(find_key(tmp[1], guess, idx, partial, at[i], end));
    } else {
      close(tmp[1]);
    }
  }

  // wait for completion
  status_t st;
  int status;
  uint32_t total_progress = 0;
  st.found = 0;
  printf("\n");
  while (num_jobs > 0) {
    if (poll(fds, num_jobs, -1) < 0) {
      perror("poll");
      break;
    }
    for (int i = 0; i < num_jobs; i++) {
      if (fds[i].revents != 0) {
        if (read_block(fds[i].fd, &st, sizeof(st)) < sizeof(st)) {
          close(fds[i].fd);
          waitpid(pids[i], &status, 0);
          fds[i].fd = fds[num_jobs-1].fd;
          pids[i] = pids[num_jobs-1];
          at[i] = at[num_jobs-1];
          num_jobs--;
        } else {
          total_progress += (st.at - at[i]);
          at[i] = st.at;

          print_progress(total_progress);

          if (st.found) {
            guess[idx] = st.at;
            break;
          }
        }
      }
    }
    if (st.found) {
      break;
    }
  }
  for (int i = 0; i < num_jobs; i++) {
    close(fds[i].fd);
    kill(pids[i], SIGTERM);
  }
  printf("\n");
  return st.found;
}

int main(int argc, const char *argv[]) {
  int threads;
  int fd;
  uint32_t guess[KEY_LEN/sizeof(uint32_t)];
  uint8_t partial[AES_BLOCK_SIZE];

  if (argc < 3) {
    fprintf(stderr, "usage: psvimg-keyfind threads partial\n");
    return 0;
  }

  threads = atoi(argv[1]);
  if (threads == 0) {
    threads = 1;
  }

  if ((fd = open(argv[2], O_RDONLY)) < 0) {
    perror("partial");
    return 0;
  }

  for (int i = 0; i < KEY_LEN/sizeof(uint32_t); i++) {
    if (read_block(fd, partial, sizeof(partial)) < sizeof(partial)) {
      fprintf(stderr, "invalid partial file\n");
      close(fd);
      return 0;
    }

    printf("Found %d/%d words, current knowledge:\n  ", i, (int)(KEY_LEN/sizeof(uint32_t)));
    print_key(guess, i*4);

    if (dispatch_jobs(threads, guess, i, partial) != 1) {
      fprintf(stderr, "brute force failed. are your partials valid?\n");
      close(fd);
      return 0;
    }
  }

  printf("Key found: ");
  print_key(guess, KEY_LEN);

  return 1;
}
