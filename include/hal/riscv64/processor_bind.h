/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PROCESSOR_BIND_H__
#define PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_RISCV64


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

typedef int64_t intn __attribute__((aligned(8)));


/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x8000000000000000ULL


/* Maximum legal RV64 address*/

#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL


/* Maximum legal RISC-V intn values.*/

#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)

#endif
