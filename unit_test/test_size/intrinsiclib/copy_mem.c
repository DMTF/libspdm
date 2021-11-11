/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Intrinsic Memory Routines Wrapper Implementation.
**/

#include <hal/base.h>
#include <hal/library/memlib.h>

#if defined(__clang__) && !defined(__APPLE__)

/* Copies bytes between buffers */
static __attribute__((__used__)) void *__memcpy(void *dest, const void *src,
						unsigned int count)
{
	return copy_mem(dest, src, (uintn)count);
}
__attribute__((__alias__("__memcpy"))) void *memcpy(void *dest, const void *src,
						    unsigned int count);

#else
/* Copies bytes between buffers */
void *memcpy(void *dest, const void *src, unsigned int count)
{
	return copy_mem(dest, src, (uintn)count);
}
#endif
