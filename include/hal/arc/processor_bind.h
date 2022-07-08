/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PROCESSOR_BIND_H
#define PROCESSOR_BIND_H


/* Define the processor type so other code can make processor based choices*/

#define LIBSPDM_CPU_ARC


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
