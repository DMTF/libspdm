/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Base Memory Allocation Routines Wrapper.
**/

#include <base.h>
#include <library/debuglib.h>
#include <library/malloclib.h>
#include <stddef.h>

//
// Extra header to record the memory buffer size from malloc routine.
//
#define CRYPTMEM_HEAD_SIGNATURE SIGNATURE_32('c', 'm', 'h', 'd')
typedef struct {
    uint32_t signature;
    uint32_t reserved;
    uintn size;
} CRYPTMEM_HEAD;

#define CRYPTMEM_OVERHEAD sizeof(CRYPTMEM_HEAD)

//
// -- Memory-Allocation Routines --
//

/* Allocates memory blocks */
void *mbedtls_calloc(size_t num, size_t size)
{
    CRYPTMEM_HEAD *pool_hdr;
    uintn new_size;
    void *data;

    //
    // Adjust the size by the buffer header overhead
    //
    new_size = (uintn)(size * num) + CRYPTMEM_OVERHEAD;

    data = allocate_zero_pool(new_size);
    if (data != NULL) {
        pool_hdr = (CRYPTMEM_HEAD *)data;
        //
        // Record the memory brief information
        //
        pool_hdr->signature = CRYPTMEM_HEAD_SIGNATURE;
        pool_hdr->size = size;

        return (void *)(pool_hdr + 1);
    } else {
        //
        // The buffer allocation failed.
        //
        return NULL;
    }
}

/* De-allocates or frees a memory block */
void mbedtls_free(void *ptr)
{
    CRYPTMEM_HEAD *pool_hdr;

    //
    // In Standard C, free() handles a null pointer argument transparently. This
    // is not true of free_pool() below, so protect it.
    //
    if (ptr != NULL) {
        pool_hdr = (CRYPTMEM_HEAD *)ptr - 1;
        ASSERT(pool_hdr->signature == CRYPTMEM_HEAD_SIGNATURE);
        free_pool(pool_hdr);
    }
}
