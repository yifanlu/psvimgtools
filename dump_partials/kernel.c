/* Copyright (C) 2017 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/sblauthmgr.h>
#include "dump_partials.h"

#define printf(...)

#define KEY_SLOT (1)

int memset(void *ptr, int ch, size_t len) {
    for (int i = 0; i < len; i += 4) {
      *(uint32_t *)(ptr + i) = ch;
    }
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *pargs) {
    args_t *args = (args_t *)pargs;

    if (argc != sizeof(*args)) {
      printf("invalid arguments\n");
      return SCE_KERNEL_START_FAILED;
    }
                                      
    int wrk = ksceKernelAllocMemBlock("wrk", 0x1050D006, 0x2000, 0);
    void *base;
    ksceKernelGetMemBlockBase(wrk, &base);
    uint8_t *src = (uint8_t*)base;
    uint8_t *dst = (uint8_t*)base + 0x1000;
    memset(base, 0, 0x2000);
    
    // Memory map the dmac5 and keyring devices
    SceKernelAllocMemBlockKernelOpt opt = {0};
    opt.size = sizeof(opt);
    opt.attr = 2;
    opt.paddr = 0xE0410000;
    int block = ksceKernelAllocMemBlock("SceDmacmgrDmac5Reg", 0x20100206, 0x1000, &opt);
    volatile uint32_t *device;
    ksceKernelGetMemBlockBase(block, (void **)&device);
    printf("dmac5 block: 0x%x | va: 0x%x\n", block, device);
    opt.size = sizeof(opt);
    opt.attr = 2;
    opt.paddr = 0xE04E0000;
    int block2 = ksceKernelAllocMemBlock("SceSblDMAC5DmacKRBase", 0x20100206, 0x1000, &opt);
    volatile uint32_t *keyring;
    ksceKernelGetMemBlockBase(block2, (void **)&keyring);
    printf("keyring block: 0x%x | va: 0x%x\n", block2, keyring);
    
    printf("start\n");
    uintptr_t src_pa, dst_pa, key_pa;
    ksceKernelGetPaddr(src, &src_pa);
    ksceKernelGetPaddr(dst, &dst_pa);
    
    #define COMMIT_WAIT device[10] = device[10]; device[7] = 1; while(device[9] & 1){};

    for (int i = 0; i < args->key_size / 4; i++) {
      // clear buffer
      memset(base, 0, 0x2000);

      // set key
      ksceSblAuthMgrClearDmac5Key(KEY_SLOT, 0);
      ksceSblAuthMgrSetDmac5Key(args->key_seed, args->key_size, KEY_SLOT, 0x10000);
      
      // clear all except one dword
      for (int j = 0; j < args->key_size / 4; j++) {
        if (i != j) {
          keyring[(8*KEY_SLOT)+j] = 0;
        }
      }

      // do encryption on zeros
      __asm__ ("dmb sy");
      __asm__ ("dsb sy");
      ksceKernelCpuDcacheAndL2WritebackRange(dst, 0x1000); 
      ksceKernelCpuDcacheAndL2WritebackRange(src, 0x1000);
      device[0] = (int)src_pa;
      device[1] = (int)dst_pa;
      device[2] = 0x10; // len
      device[3] = args->dmac5_cmd;
      device[4] = KEY_SLOT;
      device[5] = 0;
      // device[8] = 0;
      device[11] = 0xE070;
      device[12] = 0x700070;
      COMMIT_WAIT;
      __asm__ ("dmb sy");
      __asm__ ("dsb sy");     
      ksceKernelCpuDcacheAndL2InvalidateRange(dst, 0x1000);

      // write result
      ksceKernelMemcpyKernelToUser((uintptr_t)args->output + i * AES_BLOCK_SIZE, dst, AES_BLOCK_SIZE);
    }   

    #undef COMMIT_WAIT
    ksceKernelFreeMemBlock(block);
    ksceKernelFreeMemBlock(block2);
    ksceKernelFreeMemBlock(wrk);

    return SCE_KERNEL_START_NO_RESIDENT;
}
