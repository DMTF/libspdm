/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_ARM


/* Make sure we are using the correct packing rules per EFI specification*/

#if !defined(__GNUC__) && !defined(__ASSEMBLER__)
#pragma pack()
#endif

#if defined(_MSC_EXTENSIONS)


/* Disable some level 4 compilation warnings (same as IA32 and x64)*/



/* Disabling bitfield type checking warnings.*/

#pragma warning(disable : 4214)


/* Disabling the unreferenced formal parameter warnings.*/

#pragma warning(disable : 4100)


/* Disable slightly different base types warning as char * can not be set
 * to a constant string.*/

#pragma warning(disable : 4057)


/* ASSERT(false) or while (true) are legal constructs so suppress this warning*/

#pragma warning(disable : 4127)


/* This warning is caused by functions defined but not used. For precompiled header only.*/

#pragma warning(disable : 4505)


/* This warning is caused by empty (after preprocessing) source file. For precompiled header only.*/

#pragma warning(disable : 4206)


/* Disable 'potentially uninitialized local variable X used' warnings*/

#pragma warning(disable : 4701)


/* Disable 'potentially uninitialized local pointer variable X used' warnings*/

#pragma warning(disable : 4703)

#endif


/* RVCT and MSFT don't support the __builtin_unreachable() macro*/

#if defined(__armCC_VERSION) || defined(_MSC_EXTENSIONS)
#define UNREACHABLE()
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


/* Maximum legal arm address*/

#define MAX_ADDRESS 0xFFFFFFFF


/* Maximum legal arm intn values.*/

#define MAX_INTN 0x7FFFFFFF

#endif
