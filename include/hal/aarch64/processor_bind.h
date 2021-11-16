/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__

///
/// Define the processor type so other code can make processor based choices
///
#define MDE_CPU_AARCH64

//
// Make sure we are using the correct packing rules per EFI specification
//
#if !defined(__GNUC__) && !defined(__ASSEMBLER__)
#pragma pack()
#endif

#if defined(_MSC_EXTENSIONS)

//
// Disable some level 4 compilation warnings (same as IA32 and x64)
//

//
// Disabling bitfield type checking warnings.
//
#pragma warning(disable : 4214)

//
// Disabling the unreferenced formal parameter warnings.
//
#pragma warning(disable : 4100)

//
// Disable slightly different base types warning as char8 * can not be set
// to a constant string.
//
#pragma warning(disable : 4057)

//
// ASSERT(FALSE) or while (TRUE) are legal constructs so suppress this warning
//
#pragma warning(disable : 4127)

//
// This warning is caused by functions defined but not used. For precompiled header only.
//
#pragma warning(disable : 4505)

//
// This warning is caused by empty (after preprocessing) source file. For precompiled header only.
//
#pragma warning(disable : 4206)

//
// Disable 'potentially uninitialized local variable X used' warnings
//
#pragma warning(disable : 4701)

//
// Disable 'potentially uninitialized local pointer variable X used' warnings
//
#pragma warning(disable : 4703)

//
// use Microsoft* C compiler dependent integer width types
//
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char boolean;
typedef unsigned char uint8_t;
typedef char char8;
typedef signed char int8_t;

#else

//
// Assume standard AARCH64 alignment.
//
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char boolean;
typedef unsigned char uint8_t;
typedef char char8;
typedef signed char int8_t;

#endif

///
/// Unsigned value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef uint64_t uintn;

///
/// Signed value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef int64_t intn;

//
// Processor specific defines
//

///
/// A value of native width with the highest bit set.
///
#define MAX_BIT 0x8000000000000000ULL

///
/// Maximum legal AARCH64  address
///
#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL

///
/// Maximum legal aarch64 intn values.
///
#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)

#endif
