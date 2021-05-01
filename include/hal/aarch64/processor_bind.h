/** @file
  Processor or Compiler specific defines and types for aarch64.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Portions copyright (c) 2011 - 2013, arm Ltd. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

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
typedef unsigned __int64 uint64;
typedef __int64 int64;
typedef unsigned __int32 uint32;
typedef __int32 int32;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned char boolean;
typedef unsigned char uint8;
typedef char char8;
typedef signed char int8;

#else

//
// Assume standard AARCH64 alignment.
//
typedef unsigned long long uint64;
typedef long long int64;
typedef unsigned int uint32;
typedef int int32;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned char boolean;
typedef unsigned char uint8;
typedef char char8;
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
/// A value of native width with the two highest bits set.
///
#define MAX_2_BITS 0xC000000000000000ULL

///
/// Maximum legal AARCH64  address
///
#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL

///
/// Maximum usable address at boot time (48 bits using 4 KB pages)
///
#define MAX_ALLOC_ADDRESS 0xFFFFFFFFFFFFULL

///
/// Maximum legal aarch64 intn and uintn values.
///
#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)
#define MAX_UINTN ((uintn)0xFFFFFFFFFFFFFFFFULL)

///
/// Minimum legal aarch64 intn value.
///
#define MIN_INTN (((intn)-9223372036854775807LL) - 1)

///
/// The stack alignment required for AARCH64
///
#define CPU_STACK_ALIGNMENT 16

///
/// Page allocation granularity for AARCH64
///
#define DEFAULT_PAGE_ALLOCATION_GRANULARITY (0x1000)
#define RUNTIME_PAGE_ALLOCATION_GRANULARITY (0x10000)

/**
  Return the pointer to the first instruction of a function given a function pointer.
  On arm CPU architectures, these two pointer values are the same,
  so the implementation of this macro is very simple.

  @param  function_pointer   A pointer to a function.

  @return The pointer to the first instruction of a function given a function pointer.

**/
#define FUNCTION_ENTRY_POINT(function_pointer) (void *)(uintn)(function_pointer)

#ifndef __USER_LABEL_PREFIX__
#define __USER_LABEL_PREFIX__
#endif

#endif
