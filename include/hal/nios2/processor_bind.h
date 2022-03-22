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

/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x80000000

/* Maximum legal NIOS2 address*/

#define MAX_ADDRESS 0xFFFFFFFF


/* Maximum legal NIOS2 intn and size_t values.*/

#define MAX_INTN 0x7FFFFFFF

#endif
