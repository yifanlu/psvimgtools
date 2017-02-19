#include <psp2/kernel/processmgr.h>
#include <psp2/io/fcntl.h>
#include <taihen.h>
#include <stdio.h>
#include <string.h>
#include "../sha256.h"
#include "dump_partials.h"
#include "debugScreen.h"

#define MAGIC_WORDS "Sri Jayewardenepura Kotte"

const char aid[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void get_key_seed(const char aid[8], char hash[0x20]) {
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (void *)aid, 8);
    sha256_update(&ctx, MAGIC_WORDS, sizeof(MAGIC_WORDS)-1);
    sha256_final(&ctx, hash);
}

int main(int argc, char *argv[]) {
    int ret;
    int res;
    args_t arg;
    char buffer[8 * AES_BLOCK_SIZE];

    psvDebugScreenInit();

    psvDebugScreenPrintf("Started!\n");

    get_key_seed(aid, arg.key_seed);
    arg.key_size = 0x20;
    arg.dmac5_cmd = 0x301;
    arg.output = buffer;

    ret = taiLoadKernelModule("ux0:app/DUMP0900D/kernel.skprx", 0, NULL);
    if (ret < 0) {
        psvDebugScreenPrintf("Kernel load: %x\n", ret);
    } else {
        ret = taiStartKernelModule(ret, sizeof(arg), &arg, 0, NULL, &res);
    }

    psvDebugScreenPrintf("Kernel start: %x, %x\n", ret, res);

    if (ret >= 0) {
        int fd = sceIoOpen("ux0:data/partials.bin", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0x6);
        sceIoWrite(fd, buffer, sizeof(buffer));
        sceIoClose(fd);

        psvDebugScreenPrintf("Partials written.\n");
    }

    /* print at specific col;row */
    psvDebugScreenPrintf("Bye Bye");
    sceKernelDelayThread(10*1000*1000);

    sceKernelExitProcess(0);
    return 0;
}
