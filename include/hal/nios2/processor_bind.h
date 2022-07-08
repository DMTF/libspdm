/** @file
 * Processor or Compiler specific defines and types for NIOS2
 *
 * Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 **/

#ifndef PROCESSOR_BIND_H
#define PROCESSOR_BIND_H


/* Define the processor type so other code can make processor based choices*/

#define LIBSPDM_CPU_NIOS2


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

#ifndef LIBSPDM_STDDEF_ALT
#include <stddef.h>
#else
#include LIBSPDM_STDDEF_ALT
#endif

#endif /* PROCESSOR_BIND_H */
