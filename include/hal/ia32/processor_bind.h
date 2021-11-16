/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__

///
/// Define the processor type so other code can make processor based choices.
///
#define MDE_CPU_IA32

//
// Make sure we are using the correct packing rules per EFI specification
//
#if !defined(__GNUC__)
#pragma pack()
#endif

#if defined(__INTEL_COMPILER)
//
// Disable ICC's remark #869: "parameter" was never referenced warning.
// This is legal ANSI C code so we disable the remark that is turned on with -Wall
//
#pragma warning(disable : 869)

//
// Disable ICC's remark #1418: external function definition with no prior declaration.
// This is legal ANSI C code so we disable the remark that is turned on with /W4
//
#pragma warning(disable : 1418)

//
// Disable ICC's remark #1419: external declaration in primary source file
// This is legal ANSI C code so we disable the remark that is turned on with /W4
//
#pragma warning(disable : 1419)

//
// Disable ICC's remark #593: "Variable" was set but never used.
// This is legal ANSI C code so we disable the remark that is turned on with /W4
//
#pragma warning(disable : 593)

#endif

#if defined(_MSC_EXTENSIONS)

//
// Disable warning that make it impossible to compile at /W4
// This only works for Microsoft* tools
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

#if _MSC_VER == 1800 || _MSC_VER == 1900 || _MSC_VER >= 1910

//
// Disable these warnings for VS2013.
//

//
// This warning is for potentially uninitialized local variable, and it may cause false
// positive issues in VS2013 and VS2015 build
//
#pragma warning(disable : 4701)

//
// This warning is for potentially uninitialized local pointer variable, and it may cause
// false positive issues in VS2013 and VS2015 build
//
#pragma warning(disable : 4703)

#endif

#endif

#if defined(_MSC_EXTENSIONS)

//
// use Microsoft C compiler dependent integer width types
//

///
/// 8-byte unsigned value.
///
typedef unsigned __int64 uint64_t;
///
/// 8-byte signed value.
///
typedef __int64 int64_t;
///
/// 4-byte unsigned value.
///
typedef unsigned __int32 uint32_t;
///
/// 4-byte signed value.
///
typedef __int32 int32_t;
///
/// 2-byte unsigned value.
///
typedef unsigned short uint16_t;
///
/// 2-byte signed value.
///
typedef short int16_t;
///
/// Logical Boolean.  1-byte value containing 0 for FALSE or a 1 for TRUE.  Other
/// values are undefined.
///
typedef unsigned char boolean;
///
/// 1-byte unsigned value.
///
typedef unsigned char uint8_t;
///
/// 1-byte Character.
///
typedef char char8;
///
/// 1-byte signed value.
///
typedef signed char int8_t;
#else
///
/// 8-byte unsigned value.
///
typedef unsigned long long uint64_t;
///
/// 8-byte signed value.
///
typedef long long int64_t;
///
/// 4-byte unsigned value.
///
typedef unsigned int uint32_t;
///
/// 4-byte signed value.
///
typedef int int32_t;
///
/// 2-byte unsigned value.
///
typedef unsigned short uint16_t;
///
/// 2-byte signed value.
///
typedef short int16_t;
///
/// Logical Boolean.  1-byte value containing 0 for FALSE or a 1 for TRUE.  Other
/// values are undefined.
///
typedef unsigned char boolean;
///
/// 1-byte unsigned value.
///
typedef unsigned char uint8_t;
///
/// 1-byte Character
///
typedef char char8;
///
/// 1-byte signed value
///
typedef signed char int8_t;
#endif

///
/// Unsigned value of native width.  (4 bytes on supported 32-bit processor instructions;
/// 8 bytes on supported 64-bit processor instructions.)
///
typedef uint32_t uintn;
///
/// Signed value of native width.  (4 bytes on supported 32-bit processor instructions;
/// 8 bytes on supported 64-bit processor instructions.)
///
typedef int32_t intn;

//
// Processor specific defines
//

///
/// A value of native width with the highest bit set.
///
#define MAX_BIT 0x80000000

///
/// Maximum legal IA-32 address.
///
#define MAX_ADDRESS 0xFFFFFFFF

///
/// Maximum legal IA-32 intn values.
///
#define MAX_INTN ((intn)0x7FFFFFFF)

#endif
