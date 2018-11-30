/* deos_malloc.c
 *
 * Copyright (C) 2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <wolfssl/ssl.h>

#define HEAP_SIZE_MAX   (1*1024*1024)

static size_t allocatedMemory = 0;

size_t getMemAllocatedSize_does(size_t* size){

    if (size)
        *size = allocatedMemory;

    return allocatedMemory;
}

void free_deos(void *ptr) {
    //printf("fake free_deos()\n");
    return;
}

void *realloc_deos(void *ptr, size_t size) {
    void *newptr;

    if (size == 0)
        return ptr;

    newptr = malloc_deos(size);
    free_deos(ptr);

    return newptr;
}

void *malloc_deos(size_t size) {
    PDEOS_SYSTEM_INFO systemInfoPtr;
    static VirtualAddressTYP heapAddr = NULL;
    static VirtualAddressTYP freeAddr = NULL;
    VirtualAddressTYP retAddr = NULL;
    DWORD allocationSize = 0;
    static int initialized = 0;

    if (size <= 0)
        return NULL;

    if (!initialized) {
        systemInfoPtr = (PDEOS_SYSTEM_INFO)getSystemInfoDEOS();
        freeAddr = (VirtualAddressTYP)getNextLibraryStartAddress();
        allocationSize = (((HEAP_SIZE_MAX - 1) / systemInfoPtr->dwPageSize) + 1) *
                         systemInfoPtr->dwPageSize;

        if (virtualAllocDEOS(freeAddr, allocationSize) != allocSuccess){
            printf("ERROR: virtualAllocDEOS failed\n");
            return NULL;
        }

        setNextLibraryStartAddress(freeAddr + allocationSize);
        heapAddr = freeAddr;

        initialized = 1;
    }
    size = ((size + (sizeof(size_t) - 1)) & ~(sizeof(size_t) - 1));


    if (size > (HEAP_SIZE_MAX - (freeAddr - heapAddr))){
        printf("ERROR: malloc_deos cannot allocate from heap memory anymore\n");
        return NULL;
    }

    retAddr = freeAddr;
    memset(retAddr, 0, size);
    freeAddr += size;
    allocatedMemory += size;

    return retAddr;
}
