/** @file
 * Processor or Compiler specific defines and types for NIOS2
 *
 * Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 **/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_NIOS2


/* Make sure we are using the correct packing rules per EFI specification*/

#if !defined(__GNUC__)
#pragma pack()
#endif

#ifndef LIBSPDM_STDINT_ALT
#include <stdint.h>
#else
#include LIBSPDM_STDINT_ALT
#endif

#ifndef LIBSPDM_STDBOOL_ALT
#include <stdbool.h>
#else
#include LIBSPDM_STDBOOL_ALT
#endif

#include <stddef.h>

/* Signed value of native width.  (4 bytes on supported 32-bit processor instructions,
 * 8 bytes on supported 64-bit processor instructions)*/

typedef int32_t intn __attribute__((aligned(4)));


/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x80000000

/* A value of native width with the two highest bits set.*/

#define MAX_2_BITS 0xC0000000


/* Maximum legal NIOS2 address*/

#define MAX_ADDRESS 0xFFFFFFFF


/* Maximum usable address at boot time (48 bits using 4 KB pages in Supervisor mode)*/

#define MAX_ALLOC_ADDRESS MAX_ADDRESS


/* Maximum legal NIOS2 intn and size_t values.*/

#define MAX_INTN ((intn)0x7FFFFFFF)
#define MAX_UINTN ((size_t)0xFFFFFFFF)


/* The stack alignment required for NIOS2*/

#define CPU_STACK_ALIGNMENT sizeof(uint64_t)


/* Page allocation granularity for NIOS2*/

#define DEFAULT_PAGE_ALLOCATION_GRANULARITY (0x1000)
#define RUNTIME_PAGE_ALLOCATION_GRANULARITY (0x1000)

/**
 * Return the pointer to the first instruction of a function given a function pointer.
 * On x64 CPU architectures, these two pointer values are the same,
 * so the implementation of this macro is very simple.
 *
 * @param  function_pointer   A pointer to a function.
 *
 * @return The pointer to the first instruction of a function given a function pointer.
 *
 **/
#define FUNCTION_ENTRY_POINT(function_pointer) (void *)(size_t)(function_pointer)

#ifndef __USER_LABEL_PREFIX__
#define __USER_LABEL_PREFIX__
#endif

#endif
