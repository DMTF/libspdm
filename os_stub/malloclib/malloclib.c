/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void *allocate_pool(IN uintn AllocationSize)
{
    return malloc(AllocationSize);
}

void *allocate_zero_pool(IN uintn AllocationSize)
{
    void *buffer;
    buffer = malloc(AllocationSize);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, AllocationSize);
    return buffer;
}

void free_pool(IN void *buffer)
{
    free(buffer);
}
