/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2/kernel/processmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/ctrl.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/message_dialog.h>
#include <psp2/ime_dialog.h>
#include <psp2/display.h>
#include <psp2/apputil.h>
#include <psp2/gxm.h>
#include <taihen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../sha256.h"
#include "dump_partials.h"
#include "debugScreen.h"

#define MAGIC_WORDS "Sri Jayewardenepura Kotte"

static void get_key_seed(const char aid[8], char hash[0x20]) {
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (void *)aid, 8);
    sha256_update(&ctx, MAGIC_WORDS, sizeof(MAGIC_WORDS)-1);
    sha256_final(&ctx, hash);
}

#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define DISPLAY_WIDTH           960
#define DISPLAY_HEIGHT          544
#define DISPLAY_STRIDE_IN_PIXELS    1024
#define DISPLAY_BUFFER_COUNT        2
#define DISPLAY_MAX_PENDING_SWAPS   1

typedef struct{
    void*data;
    SceGxmSyncObject*sync;
    SceGxmColorSurface surf;
    SceUID uid;
}displayBuffer;

unsigned int backBufferIndex = 0;
unsigned int frontBufferIndex = 0;
/* could be converted as struct displayBuffer[] */
displayBuffer dbuf[DISPLAY_BUFFER_COUNT];

void *dram_alloc(unsigned int size, SceUID *uid){
    void *mem;
    *uid = sceKernelAllocMemBlock("gpu_mem", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW, ALIGN(size,256*1024), NULL);
    sceKernelGetMemBlockBase(*uid, &mem);
    sceGxmMapMemory(mem, ALIGN(size,256*1024), SCE_GXM_MEMORY_ATTRIB_READ | SCE_GXM_MEMORY_ATTRIB_WRITE);
    return mem;
}
void gxm_vsync_cb(const void *callback_data){
    sceDisplaySetFrameBuf(&(SceDisplayFrameBuf){sizeof(SceDisplayFrameBuf),
        *((void **)callback_data),DISPLAY_STRIDE_IN_PIXELS, 0,
        DISPLAY_WIDTH,DISPLAY_HEIGHT}, SCE_DISPLAY_SETBUF_NEXTFRAME);
}
void gxm_init(){
    sceGxmInitialize(&(SceGxmInitializeParams){0,DISPLAY_MAX_PENDING_SWAPS,gxm_vsync_cb,sizeof(void *),SCE_GXM_DEFAULT_PARAMETER_BUFFER_SIZE});
    unsigned int i;
    for (i = 0; i < DISPLAY_BUFFER_COUNT; i++) {
        dbuf[i].data = dram_alloc(4*DISPLAY_STRIDE_IN_PIXELS*DISPLAY_HEIGHT, &dbuf[i].uid);
        sceGxmColorSurfaceInit(&dbuf[i].surf,SCE_GXM_COLOR_FORMAT_A8B8G8R8,SCE_GXM_COLOR_SURFACE_LINEAR,SCE_GXM_COLOR_SURFACE_SCALE_NONE,SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT,DISPLAY_WIDTH,DISPLAY_HEIGHT,DISPLAY_STRIDE_IN_PIXELS,dbuf[i].data);
        sceGxmSyncObjectCreate(&dbuf[i].sync);
    }
}
void gxm_swap(){
    sceGxmPadHeartbeat(&dbuf[backBufferIndex].surf, dbuf[backBufferIndex].sync);
    sceGxmDisplayQueueAddEntry(dbuf[frontBufferIndex].sync, dbuf[backBufferIndex].sync, &dbuf[backBufferIndex].data);
    frontBufferIndex = backBufferIndex;
    backBufferIndex = (backBufferIndex + 1) % DISPLAY_BUFFER_COUNT;
}
void gxm_term(){
    for (int i = 0; i < DISPLAY_BUFFER_COUNT; i++) {
        sceGxmUnmapMemory(dbuf[i].data);
        sceKernelFreeMemBlock(dbuf[i].uid);
    }
    sceGxmTerminate();
}

int enter_aid(char aid[8]) {
    int ret;
    uint16_t aid_user[16 + 1];

    gxm_init();
    if (sceImeDialogInit(&(SceImeDialogParam){.title=u"Enter your AID (CMA backup folder name)", sizeof(aid_user)-1, u"", aid_user}) < 0) {
        psvDebugScreenPrintf("show dialog failed!\n");
        return -1;
    }

    while (1) {
        ret = sceImeDialogGetStatus();
        if (ret < 0) {
            break;
        } else if (ret == SCE_COMMON_DIALOG_STATUS_FINISHED) {
            SceImeDialogResult result={};
            sceImeDialogGetResult(&result);
            if (result.button != SCE_IME_DIALOG_BUTTON_CLOSE) {
                for (int i = 0; i < 8; i++) {
                    char tmp[3];
                    tmp[0] = aid_user[2*i];
                    tmp[1] = aid_user[2*i+1];
                    tmp[2] = '\0';
                    aid[i] = strtol(tmp, NULL, 16);
                }
            }
            break;
        }

        sceCommonDialogUpdate(&(SceCommonDialogUpdateParam){{
            NULL,dbuf[backBufferIndex].data,0,0,
            DISPLAY_WIDTH,DISPLAY_HEIGHT,DISPLAY_STRIDE_IN_PIXELS},
            dbuf[backBufferIndex].sync});

        gxm_swap();
        sceDisplayWaitVblankStart();
    }
    gxm_term();
    sceImeDialogTerm();
    return ret;
}

int get_aid_from_ux0(char aid[8]) {
    int fd;
    char buf[1024];
    char *at;

    memset(buf, 0, sizeof(buf));
    fd = sceIoOpen("ux0:id.dat", SCE_O_RDONLY, 0);
    if (fd >= 0) {
        sceIoRead(fd, buf, sizeof(buf)-1);
        at = strstr(buf, "\r\nAID=");
        if (at != NULL) {
            for (int i = 0; i < 8; i++) {
                char tmp[3];
                *(uint16_t *)tmp = *(uint16_t *)&at[6 + 2*i];
                tmp[2] = '\0';
                aid[8-i-1] = strtol(tmp, NULL, 16);
            }
        }
        sceIoClose(fd);
    }

    return fd;
}

const char *aid_string(const char aid[8], char *buf) {
    for (int i = 0; i < 8; i++) {
        snprintf(buf + 2*i, 3, "%02X", (unsigned char)aid[i]);
    }
    return buf;
}

int dump_partials(char aid[8]) {
    args_t arg;
    char path[256];
    char buffer[8 * AES_BLOCK_SIZE];
    char tmp[16+1];
    int ret, res;

    get_key_seed(aid, arg.key_seed);
    arg.key_size = 0x20;
    arg.dmac5_cmd = 0x301;
    arg.output = buffer;

    snprintf(path, 256, "ux0:data/partials-%s.bin", aid_string(aid, tmp));

    ret = taiLoadKernelModule("ux0:app/DUMP0900D/kernel.skprx", 0, NULL);
    if (ret < 0) {
        psvDebugScreenPrintf("Kernel load: %x\n", ret);
    } else {
        ret = taiStartKernelModule(ret, sizeof(arg), &arg, 0, NULL, &res);
    }

    psvDebugScreenPrintf("Kernel start: %x, %x\n", ret, res);

    if (ret >= 0) {
        int fd = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0x6);
        sceIoWrite(fd, buffer, sizeof(buffer));
        sceIoClose(fd);

        psvDebugScreenPrintf("Partials written to %s.\n\n", path);
    }

    return ret;
}

int main(int argc, char *argv[]) {
    char aid[8];
    char tmp[16+1];

    psvDebugScreenInit();
    sceAppUtilInit(&(SceAppUtilInitParam){}, &(SceAppUtilBootParam){});
    sceCommonDialogSetConfigParam(&(SceCommonDialogConfigParam){});

    psvDebugScreenPrintf("Started!\n\n");
    memset(aid, 0, sizeof(aid));
    get_aid_from_ux0(aid);

    while (1) {
        psvDebugScreenPrintf("Your AID is: %s\n\n", aid_string(aid, tmp));
        psvDebugScreenPrintf("Press Square to enter a new AID to dump.\nPress X to dump partials.\nPress Circle to exit.\n\n");

        SceCtrlData ctrl;
        do {
            sceCtrlPeekBufferPositive(0, &ctrl, 1);
        } while ((ctrl.buttons & (SCE_CTRL_SQUARE | SCE_CTRL_CROSS | SCE_CTRL_CIRCLE)) == 0);

        if (ctrl.buttons & SCE_CTRL_CIRCLE) {
            break;
        } else if (ctrl.buttons & SCE_CTRL_SQUARE) {
            enter_aid(aid);
            psvDebugScreenSet();
        } else if (ctrl.buttons & SCE_CTRL_CROSS) {
            dump_partials(aid);
            sceKernelDelayThread(1*1000*1000);
        }
    }

    return 0;
}
