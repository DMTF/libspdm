/** @file
  Processor or Compiler specific defines and types for RISC-V

  Copyright (c) 2016 - 2020, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef PROCESSOR_BIND_H__
#define PROCESSOR_BIND_H__

///
/// Define the processor type so other code can make processor based choices
///
#define MDE_CPU_RISCV64

//
// Make sure we are using the correct packing rules per EFI specification
//
#if !defined(__GNUC__)
#pragma pack()
#endif

///
/// 8-byte unsigned value
///
typedef unsigned long long uint64 __attribute__((aligned(8)));
///
/// 8-byte signed value
///
typedef long long int64 __attribute__((aligned(8)));
///
/// 4-byte unsigned value
///
typedef unsigned int uint32 __attribute__((aligned(4)));
///
/// 4-byte signed value
///
typedef int int32 __attribute__((aligned(4)));
///
/// 2-byte unsigned value
///
typedef unsigned short uint16 __attribute__((aligned(2)));
///
/// 2-byte signed value
///
typedef short int16 __attribute__((aligned(2)));
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
///
/// Unsigned value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef uint64 uintn __attribute__((aligned(8)));
///
/// Signed value of native width.  (4 bytes on supported 32-bit processor instructions,
/// 8 bytes on supported 64-bit processor instructions)
///
typedef int64 intn __attribute__((aligned(8)));

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
/// Maximum legal RV64 address
///
#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL

///
/// Maximum usable address at boot time (48 bits using 4 KB pages in Supervisor mode)
///
#define MAX_ALLOC_ADDRESS 0xFFFFFFFFFFFFULL

///
/// Maximum legal RISC-V intn and uintn values.
///
#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)
#define MAX_UINTN ((uintn)0xFFFFFFFFFFFFFFFFULL)

///
/// The stack alignment required for RISC-V
///
#define CPU_STACK_ALIGNMENT 16

///
/// Page allocation granularity for RISC-V
///
#define DEFAULT_PAGE_ALLOCATION_GRANULARITY (0x1000)
#define RUNTIME_PAGE_ALLOCATION_GRANULARITY (0x1000)

/**
  Return the pointer to the first instruction of a function given a function pointer.
  On x64 CPU architectures, these two pointer values are the same,
  so the implementation of this macro is very simple.

  @param  function_pointer   A pointer to a function.

  @return The pointer to the first instruction of a function given a function pointer.

**/
#define FUNCTION_ENTRY_POINT(function_pointer) (void *)(uintn)(function_pointer)

#ifndef __USER_LABEL_PREFIX__
#define __USER_LABEL_PREFIX__
#endif

#endif
