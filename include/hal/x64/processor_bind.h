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
#define MDE_CPU_X64

//
// Make sure we are using the correct packing rules per EFI specification
//
#if !defined(__GNUC__)
#pragma pack()
#endif

#if defined(__GNUC__) && defined(__pic__) && !defined(USING_LTO) &&            \
	!defined(__APPLE__)
//
// Mark all symbol declarations and references as hidden, meaning they will
// not be subject to symbol preemption. This allows the compiler to refer to
// symbols directly using relative references rather than via the GOT, which
// contains absolute symbol addresses that are subject to runtime relocation.
//
// The LTO linker will not emit GOT based relocations when all symbol
// references can be resolved locally, and so there is no need to set the
// pragma in that case (and doing so will cause other issues).
//
#pragma GCC visibility push(hidden)
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
/// 8-byte unsigned value
///
typedef unsigned __int64 uint64;
///
/// 8-byte signed value
///
typedef __int64 int64;
///
/// 4-byte unsigned value
///
typedef unsigned __int32 uint32;
///
/// 4-byte signed value
///
typedef __int32 int32;
///
/// 2-byte unsigned value
///
typedef unsigned short uint16;
///
/// 2-byte signed value
///
typedef short int16;
///
/// Logical Boolean.  1-byte value containing 0 for FALSE or a 1 for TRUE.  Other
/// values are undefined.
///
typedef unsigned char boolean;
///
/// 1-byte unsigned value
///
typedef unsigned char uint8;
///
/// 1-byte Character
///
typedef char char8;
///
/// 1-byte signed value
///
typedef signed char int8;
#else
///
/// 8-byte unsigned value
///
typedef unsigned long long uint64;
///
/// 8-byte signed value
///
typedef long long int64;
///
/// 4-byte unsigned value
///
typedef unsigned int uint32;
///
/// 4-byte signed value
///
typedef int int32;
///
/// 2-byte unsigned value
///
typedef unsigned short uint16;
///
/// 2-byte signed value
///
typedef short int16;
///
/// Logical Boolean.  1-byte value containing 0 for FALSE or a 1 for TRUE.  Other
/// values are undefined.
///
typedef unsigned char boolean;
///
/// 1-byte unsigned value
///
typedef unsigned char uint8;
///
/// 1-byte Character
///
typedef char char8;
///
/// 1-byte signed value
///
typedef signed char int8;
#endif

///
/// Unsigned value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef uint64 uintn;
///
/// Signed value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef int64 intn;

//
// Processor specific defines
//

///
/// A value of native width with the highest bit set.
///
#define MAX_BIT 0x8000000000000000ULL

///
/// Maximum legal x64 address
///
#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL

///
/// Maximum legal x64 intn values.
///
#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)

#endif
