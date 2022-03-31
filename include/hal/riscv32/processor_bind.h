/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PROCESSOR_BIND_H__
#define PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_RISCV32


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

/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x80000000


/* Maximum legal RV32 address*/

#define MAX_ADDRESS 0xFFFFFFFF


/* Maximum legal RISC-V intn values.*/

#define MAX_INTN 0x7FFFFFFF

#endif
