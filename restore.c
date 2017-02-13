/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <zlib.h>
#include "aes.h"
#include "endian-utils.h"
#include "restore.h"
#include "sha256.h"
#include "psvimg.h"
#include "utils.h"

#define MAX_PATH_LEN 1024

static void print_hash(const char *title, uint8_t hash[SHA256_MAC_LEN]) {
  fprintf(stderr, "%s: ", title);
  for (int i = 0; i < SHA256_MAC_LEN; i++) {
    fprintf(stderr, "%02X", hash[i]);
  }
  fprintf(stderr, "\n");
}

void *decrypt_thread(void *pargs) {
  args_t *args = (args_t *)pargs;
  SHA256_CTX ctx, tmp;
  uint8_t iv[AES_BLOCK_SIZE];
  uint8_t next_iv[AES_BLOCK_SIZE];
  uint8_t hash[SHA256_MAC_LEN];
  uint8_t buffer[PSVIMG_BLOCK_SIZE + SHA256_MAC_LEN];
  ssize_t rd, total;

  // read iv
  if (read_block(args->in, iv, AES_BLOCK_SIZE) < AES_BLOCK_SIZE) {
    fprintf(stderr, "file too small! cannot read IV!\n");
    goto end;
  }

  // decrypt blocks
  sha256_init(&ctx);
  total = AES_BLOCK_SIZE;
  while ((rd = read_block(args->in, buffer, sizeof(buffer))) > 0) {
    // save next iv
    memcpy(next_iv, &buffer[rd - AES_BLOCK_SIZE], AES_BLOCK_SIZE);

    // decrypt
    aes256_cbc_decrypt(buffer, args->key, iv, rd / AES_BLOCK_SIZE);

    if (rd != sizeof(buffer)) {
      total += rd;
      break; // last block requires special processing
    }

    // TODO: there's actually a bug in Sony's implementation where 
    // if the last block is exactly 0x8000 (before the SHA256) then 
    // it won't know about the last block and terminate in error. 
    // In other words, we don't have to handle this edge case... for now.

    // validate hash
    sha256_update(&ctx, buffer, rd - SHA256_MAC_LEN);
    tmp = ctx;
    sha256_final(&tmp, hash);
    if (memcmp(&buffer[rd-SHA256_MAC_LEN], hash, SHA256_MAC_LEN) != 0) {
      fprintf(stderr, "hash mismatch at offset 0x%zx, (buffer size 0x%zx)\n", total - SHA256_MAC_LEN, rd);
      print_hash("expected", &buffer[rd-SHA256_MAC_LEN]);
      print_hash("actual", hash);
      goto end;
    }

    // write output
    write_block(args->out, buffer, rd - SHA256_MAC_LEN);

    memcpy(iv, next_iv, AES_BLOCK_SIZE);
    total += rd;
  }

  if (rd < 0) {
    fprintf(stderr, "Read error occured!\n");
    goto end;
  }

  // handle last block specially
  uint64_t exp_total;
  uint32_t exp_padding;

  exp_padding = le32toh(*(uint32_t *)&buffer[rd-0x10]);
  exp_total = le64toh(*(uint64_t *)&buffer[rd-0x8]);
  if (exp_total != total) {
    fprintf(stderr, "read size mismatch. expected: 0x%llx, actual: 0x%zx\n", exp_total, total);
    goto end;
  }
  exp_padding += 0x10;
  sha256_update(&ctx, buffer, rd - SHA256_MAC_LEN - exp_padding);
  tmp = ctx;
  sha256_final(&tmp, hash);
  if (memcmp(&buffer[rd-SHA256_MAC_LEN-exp_padding], hash, SHA256_MAC_LEN) != 0) {
    fprintf(stderr, "hash mismatch at offset 0x%lx, (buffer size 0x%zx)\n", total - SHA256_MAC_LEN - exp_padding, rd);
    print_hash("expected", &buffer[rd-SHA256_MAC_LEN]);
    print_hash("actual", hash);
    goto end;
  }

  write_block(args->out, buffer, rd - SHA256_MAC_LEN - exp_padding);

end:
  close(args->out);
  close(args->in);
  return NULL;
}

void *decompress_thread(void *pargs) {
  args_t *args = (args_t *)pargs;

  int ret;
  unsigned have;
  z_stream strm;
  unsigned char in[PSVIMG_BLOCK_SIZE];
  unsigned char out[PSVIMG_BLOCK_SIZE];
  ssize_t rd;

  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  ret = inflateInit(&strm);
  if (ret != Z_OK) {
    fprintf(stderr, "error init zlib\n");
    goto end;
  }

  /* decompress until deflate stream ends or end of file */
  do {
    strm.avail_in = rd = read_block(args->in, in, sizeof(in));
    if (rd < 0) {
      fprintf(stderr, "error reading\n");
      goto end;
    }
    if (strm.avail_in == 0)
      break;
    strm.next_in = in;

    /* run inflate() on input until output buffer not full */
    do {
      strm.avail_out = PSVIMG_BLOCK_SIZE;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      switch (ret) {
      case Z_NEED_DICT:
        ret = Z_DATA_ERROR;     /* and fall through */
      case Z_DATA_ERROR:
      case Z_MEM_ERROR:
        fprintf(stderr, "error inflating (bad file?)\n");
        (void)inflateEnd(&strm);
        goto end;
      }
      have = PSVIMG_BLOCK_SIZE - strm.avail_out;
      if (write_block(args->out, out, have) < have) {
        fprintf(stderr, "error writing\n");
        goto end;
      }
    } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  (void)inflateEnd(&strm);

end:
  close(args->out);
  close(args->in);
  return NULL;
}

static void sanatize_name(const char *bad, char *good, int len) {
  size_t sz;

  sz = strnlen(bad, len);
  for (int i = 0; i < sz; i++) {
    if (bad[i] == ':') {
      good[i] = '_';
    } else if (bad[i] == '/') {
      good[i] = '_';
    } else if (bad[i] == '\\') {
      good[i] = '_';
    } else {
      good[i] = bad[i];
    }
  }
  good[sz] = '\0';
}

static void scetime_to_tm(SceDateTime *sce, struct tm *tm) {
  tm->tm_sec = le16toh(sce->second);
  tm->tm_min = le16toh(sce->minute);
  tm->tm_hour = le16toh(sce->hour);
  tm->tm_mday = le16toh(sce->day);
  tm->tm_mon = le16toh(sce->month) - 1;
  tm->tm_year = le16toh(sce->year) - 1900;
  tm->tm_wday = 0;
  tm->tm_yday = 0;
  tm->tm_isdst = 0;
}

static mode_t scemode_to_posix(int sce_mode) {
  int mode = 0;
  if ((sce_mode & SCE_S_IRUSR) == SCE_S_IRUSR) {
    mode |= S_IRUSR;
  }
  if ((sce_mode & SCE_S_IWUSR) == SCE_S_IWUSR) {
    mode |= S_IWUSR;
  }
  if ((sce_mode & SCE_S_IRGRP) == SCE_S_IRGRP) {
    mode |= S_IRGRP;
  }
  if ((sce_mode & SCE_S_IWGRP) == SCE_S_IWGRP) {
    mode |= S_IWGRP;
  }
  if ((sce_mode & SCE_S_IROTH) == SCE_S_IROTH) {
    mode |= S_IROTH;
  }
  if ((sce_mode & SCE_S_IWOTH) == SCE_S_IWOTH) {
    mode |= S_IWOTH;
  }
  return mode;
}

static void write_file(PsvImgHeader_t *header, char *data, const char *prefix) {
  char good_parent[256];
  char full_parent[MAX_PATH_LEN];
  char full_path[MAX_PATH_LEN];
  struct stat st;
  int fd;
  struct tm tm;
  struct utimbuf times;

  sanatize_name(header->path_parent, good_parent, 256);
  snprintf(full_parent, MAX_PATH_LEN, "%s/%s", prefix, good_parent);

  // create parent directory if needed
  if (stat(full_parent, &st) < 0) {
    mkdir(full_parent, 0700);
    snprintf(full_path, MAX_PATH_LEN, "%s/%s", full_parent, "VITA_PATH.TXT");
    fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write_block(fd, header->path_parent, strnlen(header->path_parent, 256));
    close(fd);
  }

  // create file
  if (header->path_rel[0] == '\0') {
    strcpy(header->path_rel, "VITA_DATA.BIN");
  }
  snprintf(full_path, MAX_PATH_LEN, "%s/%s", full_parent, header->path_rel);
  if (SCE_S_ISREG(le32toh(header->stat.sst_mode))) {
    fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, scemode_to_posix(le32toh(header->stat.sst_mode)));
    write_block(fd, data, le64toh(header->stat.sst_size));
    close(fd);
  } else {
    mkdir(full_path, scemode_to_posix(le32toh(header->stat.sst_mode)));
  }

  // set creation time
  scetime_to_tm(&header->stat.sst_atime, &tm);
  times.actime = mktime(&tm);
  scetime_to_tm(&header->stat.sst_mtime, &tm);
  times.modtime = mktime(&tm);
  utime(full_path, &times);
}

void *unpack_thread(void *pargs) {
  args_t *args = (args_t *)pargs;
  PsvImgHeader_t header;
  PsvImgTailer_t tailer;
  int padding;
  char *buffer;
  uint64_t fsize;

  while (read_block(args->in, &header, sizeof(header)) > 0) {
    if (memcmp(header.end, PSVIMG_ENDOFHEADER, sizeof(header.end)) != 0) {
      fprintf(stderr, "invalid header (bad file?)\n");
      goto end;
    }

    if (SCE_S_ISREG(le32toh(header.stat.sst_mode))) {
      fsize = le64toh(header.stat.sst_size);
      printf("creating file %s%s (%llx bytes)...\n", header.path_parent, header.path_rel, fsize);
    } else {
      fsize = 0;
      printf("creating directory %s%s...\n", header.path_parent, header.path_rel);
    }

    buffer = malloc(fsize);
    if (read_block(args->in, buffer, fsize) < fsize) {
      free(buffer);
      fprintf(stderr, "error reading %s\n", header.path_rel);
      goto end;
    }
    write_file(&header, buffer, args->prefix);
    free(buffer);

    // read padding
    if (fsize & (PSVIMG_ENTRY_ALIGN-1)) {
      padding = PSVIMG_ENTRY_ALIGN - (fsize & (PSVIMG_ENTRY_ALIGN-1));
    } else {
      padding = 0;
    }
    buffer = malloc(padding);
    if (read_block(args->in, buffer, padding) < padding) {
      free(buffer);
      fprintf(stderr, "error reading padding\n");
      goto end;
    }
    free(buffer);

    // read tailer
    if (read_block(args->in, &tailer, sizeof(tailer)) < sizeof(tailer)) {
      fprintf(stderr, "error reading tailer\n");
      goto end;
    }

    if (memcmp(tailer.end, PSVIMG_ENDOFTAILER, sizeof(tailer.end)) != 0) {
      fprintf(stderr, "invalid tailer (bad file?)\n");
      goto end;
    }
  }
  
end:
  close(args->out);
  close(args->in);
  return NULL;
}
