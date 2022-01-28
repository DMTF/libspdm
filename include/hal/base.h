/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __BASE_H__
#define __BASE_H__


/* Include processor specific binding*/

#include <processor_bind.h>

#if defined(_MSC_EXTENSIONS)

/* Disable warning when last field of data structure is a zero sized array.*/

#pragma warning(disable : 4200)
#endif


/* The Microsoft* C compiler can removed references to unreferenced data items*/
/*  if the /OPT:REF linker option is used. We defined a macro as this is a*/
/*  a non standard extension*/

#if defined(_MSC_EXTENSIONS) && _MSC_VER < 1800 && !defined(MDE_CPU_EBC)

/* Remove global variable from the linked image if there are no references to*/
/* it after all compiler and linker optimizations have been performed.*/


#define GLOBAL_REMOVE_IF_UNREFERENCED __declspec(selectany)
#else

/* Remove the global variable from the linked image if there are no references*/
/*  to it after all compiler and linker optimizations have been performed.*/


#define GLOBAL_REMOVE_IF_UNREFERENCED
#endif


/* Should be used in combination with NORETURN to avoid 'noreturn' returns*/
/* warnings.*/

#ifndef UNREACHABLE
#ifdef __GNUC__

/* Signal compilers and analyzers that this call is not reachable.  It is*/
/* up to the compiler to remove any code past that point.*/

#define UNREACHABLE() __builtin_unreachable()
#elif defined(__has_feature)
#if __has_builtin(__builtin_unreachable)

/* Signal compilers and analyzers that this call is not reachable.  It is*/
/* up to the compiler to remove any code past that point.*/

#define UNREACHABLE() __builtin_unreachable()
#endif
#endif

#ifndef UNREACHABLE

/* Signal compilers and analyzers that this call is not reachable.  It is*/
/* up to the compiler to remove any code past that point.*/

#define UNREACHABLE()
#endif
#endif


/* Signaling compilers and analyzers that a certain function cannot return may*/
/* remove all following code and thus lead to better optimization and less*/
/* false positives.*/

#ifndef NORETURN
#if defined(__GNUC__) || defined(__clang__)

/* Signal compilers and analyzers that the function cannot return.*/
/* It is up to the compiler to remove any code past a call to functions*/
/* flagged with this attribute.*/

#define NORETURN __attribute__((noreturn))
#elif defined(_MSC_EXTENSIONS) && !defined(MDE_CPU_EBC)

/* Signal compilers and analyzers that the function cannot return.*/
/* It is up to the compiler to remove any code past a call to functions*/
/* flagged with this attribute.*/

#define NORETURN __declspec(noreturn)
#else

/* Signal compilers and analyzers that the function cannot return.*/
/* It is up to the compiler to remove any code past a call to functions*/
/* flagged with this attribute.*/

#define NORETURN
#endif
#endif


/* Should be used in combination with ANALYZER_NORETURN to avoid 'noreturn'*/
/* returns warnings.*/

#ifndef ANALYZER_UNREACHABLE
#ifdef __clang_analyzer__
#if __has_builtin(__builtin_unreachable)

/* Signal the analyzer that this call is not reachable.*/
/* This excludes compilers.*/

#define ANALYZER_UNREACHABLE() __builtin_unreachable()
#endif
#endif

#ifndef ANALYZER_UNREACHABLE

/* Signal the analyzer that this call is not reachable.*/
/* This excludes compilers.*/

#define ANALYZER_UNREACHABLE()
#endif
#endif


/* Static Analyzers may issue errors about potential NULL-dereferences when*/
/* dereferencing a pointer, that has been checked before, outside of a*/
/* NULL-check.  This may lead to false positives, such as when using ASSERT()*/
/* for verification.*/

#ifndef ANALYZER_NORETURN
#ifdef __has_feature
#if __has_feature(attribute_analyzer_noreturn)

/* Signal analyzers that the function cannot return.*/
/* This excludes compilers.*/

#define ANALYZER_NORETURN __attribute__((analyzer_noreturn))
#endif
#endif

#ifndef ANALYZER_NORETURN

/* Signal the analyzer that the function cannot return.*/
/* This excludes compilers.*/

#define ANALYZER_NORETURN
#endif
#endif


/* Tell the code optimizer that the function will return twice.*/
/* This prevents wrong optimizations which can cause bugs.*/

#ifndef RETURNS_TWICE
#if defined(__GNUC__) || defined(__clang__)

/* Tell the code optimizer that the function will return twice.*/
/* This prevents wrong optimizations which can cause bugs.*/

#define RETURNS_TWICE __attribute__((returns_twice))
#else

/* Tell the code optimizer that the function will return twice.*/
/* This prevents wrong optimizations which can cause bugs.*/

#define RETURNS_TWICE
#endif
#endif


/* For symbol name in assembly code, an extra "_" is sometimes necessary*/


#if __APPLE__

/* Apple extension that is used by the linker to optimize code size*/
/* with assembly functions. Put at the end of your .S files*/

#define ASM_FUNCTION_REMOVE_IF_UNREFERENCED .subsections_via_symbols
#else
#define ASM_FUNCTION_REMOVE_IF_UNREFERENCED
#endif

#ifdef __CC_arm

/* Older RVCT arm compilers don't fully support #pragma pack and require __packed*/
/* as a prefix for the structure.*/

#define PACKED __packed
#else
#define PACKED
#endif


/* Modifiers for data Types used to self document code.*/



/* Datum is passed to the function.*/

#define IN


/* Datum is returned from the function.*/

#define OUT


/* Passing the datum to the function is optional, and a NULL*/
/* is passed if the value is not supplied.*/

#define OPTIONAL


/* Boolean true value.*/

#define TRUE ((boolean)(1 == 1))


/* Boolean false value.*/

#define FALSE ((boolean)(0 == 1))


/* NULL pointer (void *)*/

#define NULL ((void *)0)


/* Maximum values for common data Types*/

#define MAX_INT8 ((int8_t)0x7F)
#define MAX_UINT8 ((uint8_t)0xFF)
#define MAX_INT16 ((int16_t)0x7FFF)
#define MAX_UINT16 ((uint16_t)0xFFFF)
#define MAX_INT32 ((int32_t)0x7FFFFFFF)
#define MAX_UINT32 ((uint32_t)0xFFFFFFFF)
#define MAX_INT64 ((int64_t)0x7FFFFFFFFFFFFFFFULL)
#define MAX_UINT64 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)


/* Minimum values for the signed data Types*/

#define MIN_INT8 (((int8_t)-127) - 1)
#define MIN_INT16 (((int16_t)-32767) - 1)
#define MIN_INT32 (((int32_t)-2147483647) - 1)
#define MIN_INT64 (((int64_t)-9223372036854775807LL) - 1)

#define BIT0 0x00000001
#define BIT1 0x00000002
#define BIT2 0x00000004
#define BIT3 0x00000008
#define BIT4 0x00000010
#define BIT5 0x00000020
#define BIT6 0x00000040
#define BIT7 0x00000080
#define BIT8 0x00000100
#define BIT9 0x00000200
#define BIT10 0x00000400
#define BIT11 0x00000800
#define BIT12 0x00001000
#define BIT13 0x00002000
#define BIT14 0x00004000
#define BIT15 0x00008000
#define BIT16 0x00010000
#define BIT17 0x00020000
#define BIT18 0x00040000
#define BIT19 0x00080000
#define BIT20 0x00100000
#define BIT21 0x00200000
#define BIT22 0x00400000
#define BIT23 0x00800000
#define BIT24 0x01000000
#define BIT25 0x02000000
#define BIT26 0x04000000
#define BIT27 0x08000000
#define BIT28 0x10000000
#define BIT29 0x20000000
#define BIT30 0x40000000
#define BIT31 0x80000000
#define BIT32 0x0000000100000000ULL
#define BIT33 0x0000000200000000ULL
#define BIT34 0x0000000400000000ULL
#define BIT35 0x0000000800000000ULL
#define BIT36 0x0000001000000000ULL
#define BIT37 0x0000002000000000ULL
#define BIT38 0x0000004000000000ULL
#define BIT39 0x0000008000000000ULL
#define BIT40 0x0000010000000000ULL
#define BIT41 0x0000020000000000ULL
#define BIT42 0x0000040000000000ULL
#define BIT43 0x0000080000000000ULL
#define BIT44 0x0000100000000000ULL
#define BIT45 0x0000200000000000ULL
#define BIT46 0x0000400000000000ULL
#define BIT47 0x0000800000000000ULL
#define BIT48 0x0001000000000000ULL
#define BIT49 0x0002000000000000ULL
#define BIT50 0x0004000000000000ULL
#define BIT51 0x0008000000000000ULL
#define BIT52 0x0010000000000000ULL
#define BIT53 0x0020000000000000ULL
#define BIT54 0x0040000000000000ULL
#define BIT55 0x0080000000000000ULL
#define BIT56 0x0100000000000000ULL
#define BIT57 0x0200000000000000ULL
#define BIT58 0x0400000000000000ULL
#define BIT59 0x0800000000000000ULL
#define BIT60 0x1000000000000000ULL
#define BIT61 0x2000000000000000ULL
#define BIT62 0x4000000000000000ULL
#define BIT63 0x8000000000000000ULL

#define SIZE_1KB 0x00000400
#define SIZE_2KB 0x00000800
#define SIZE_4KB 0x00001000
#define SIZE_8KB 0x00002000
#define SIZE_16KB 0x00004000
#define SIZE_32KB 0x00008000
#define SIZE_64KB 0x00010000
#define SIZE_128KB 0x00020000
#define SIZE_256KB 0x00040000
#define SIZE_512KB 0x00080000
#define SIZE_1MB 0x00100000
#define SIZE_2MB 0x00200000
#define SIZE_4MB 0x00400000
#define SIZE_8MB 0x00800000
#define SIZE_16MB 0x01000000
#define SIZE_32MB 0x02000000
#define SIZE_64MB 0x04000000
#define SIZE_128MB 0x08000000
#define SIZE_256MB 0x10000000
#define SIZE_512MB 0x20000000
#define SIZE_1GB 0x40000000
#define SIZE_2GB 0x80000000
#define SIZE_4GB 0x0000000100000000ULL
#define SIZE_8GB 0x0000000200000000ULL
#define SIZE_16GB 0x0000000400000000ULL
#define SIZE_32GB 0x0000000800000000ULL
#define SIZE_64GB 0x0000001000000000ULL
#define SIZE_128GB 0x0000002000000000ULL
#define SIZE_256GB 0x0000004000000000ULL
#define SIZE_512GB 0x0000008000000000ULL
#define SIZE_1TB 0x0000010000000000ULL
#define SIZE_2TB 0x0000020000000000ULL
#define SIZE_4TB 0x0000040000000000ULL
#define SIZE_8TB 0x0000080000000000ULL
#define SIZE_16TB 0x0000100000000000ULL
#define SIZE_32TB 0x0000200000000000ULL
#define SIZE_64TB 0x0000400000000000ULL
#define SIZE_128TB 0x0000800000000000ULL
#define SIZE_256TB 0x0001000000000000ULL
#define SIZE_512TB 0x0002000000000000ULL
#define SIZE_1PB 0x0004000000000000ULL
#define SIZE_2PB 0x0008000000000000ULL
#define SIZE_4PB 0x0010000000000000ULL
#define SIZE_8PB 0x0020000000000000ULL
#define SIZE_16PB 0x0040000000000000ULL
#define SIZE_32PB 0x0080000000000000ULL
#define SIZE_64PB 0x0100000000000000ULL
#define SIZE_128PB 0x0200000000000000ULL
#define SIZE_256PB 0x0400000000000000ULL
#define SIZE_512PB 0x0800000000000000ULL
#define SIZE_1EB 0x1000000000000000ULL
#define SIZE_2EB 0x2000000000000000ULL
#define SIZE_4EB 0x4000000000000000ULL
#define SIZE_8EB 0x8000000000000000ULL

#define BASE_1KB 0x00000400
#define BASE_2KB 0x00000800
#define BASE_4KB 0x00001000
#define BASE_8KB 0x00002000
#define BASE_16KB 0x00004000
#define BASE_32KB 0x00008000
#define BASE_64KB 0x00010000
#define BASE_128KB 0x00020000
#define BASE_256KB 0x00040000
#define BASE_512KB 0x00080000
#define BASE_1MB 0x00100000
#define BASE_2MB 0x00200000
#define BASE_4MB 0x00400000
#define BASE_8MB 0x00800000
#define BASE_16MB 0x01000000
#define BASE_32MB 0x02000000
#define BASE_64MB 0x04000000
#define BASE_128MB 0x08000000
#define BASE_256MB 0x10000000
#define BASE_512MB 0x20000000
#define BASE_1GB 0x40000000
#define BASE_2GB 0x80000000
#define BASE_4GB 0x0000000100000000ULL
#define BASE_8GB 0x0000000200000000ULL
#define BASE_16GB 0x0000000400000000ULL
#define BASE_32GB 0x0000000800000000ULL
#define BASE_64GB 0x0000001000000000ULL
#define BASE_128GB 0x0000002000000000ULL
#define BASE_256GB 0x0000004000000000ULL
#define BASE_512GB 0x0000008000000000ULL
#define BASE_1TB 0x0000010000000000ULL
#define BASE_2TB 0x0000020000000000ULL
#define BASE_4TB 0x0000040000000000ULL
#define BASE_8TB 0x0000080000000000ULL
#define BASE_16TB 0x0000100000000000ULL
#define BASE_32TB 0x0000200000000000ULL
#define BASE_64TB 0x0000400000000000ULL
#define BASE_128TB 0x0000800000000000ULL
#define BASE_256TB 0x0001000000000000ULL
#define BASE_512TB 0x0002000000000000ULL
#define BASE_1PB 0x0004000000000000ULL
#define BASE_2PB 0x0008000000000000ULL
#define BASE_4PB 0x0010000000000000ULL
#define BASE_8PB 0x0020000000000000ULL
#define BASE_16PB 0x0040000000000000ULL
#define BASE_32PB 0x0080000000000000ULL
#define BASE_64PB 0x0100000000000000ULL
#define BASE_128PB 0x0200000000000000ULL
#define BASE_256PB 0x0400000000000000ULL
#define BASE_512PB 0x0800000000000000ULL
#define BASE_1EB 0x1000000000000000ULL
#define BASE_2EB 0x2000000000000000ULL
#define BASE_4EB 0x4000000000000000ULL
#define BASE_8EB 0x8000000000000000ULL

/**
  Return the size of argument that has been aligned to sizeof (uintn).

  @param  n    The parameter size to be aligned.

  @return The aligned size.
**/
#define _INT_SIZE_OF(n) ((sizeof(n) + sizeof(uintn) - 1) & ~(sizeof(uintn) - 1))

#if defined(__CC_arm)

/* RVCT arm variable argument list support.*/



/* Variable used to traverse the list of arguments. This type can vary by*/
/* implementation and could be an array or structure.*/

#ifdef __APCS_ADSABI
typedef int *va_list[1];
#define VA_LIST va_list
#else
typedef struct __va_list {
    void *__ap;
} va_list;
#define VA_LIST va_list
#endif

#define VA_START(marker, parameter) __va_start(marker, parameter)

#define VA_ARG(marker, TYPE) __va_arg(marker, TYPE)

#define VA_END(marker) ((void)0)

/* For some arm RVCT compilers, __va_copy is not defined*/
#ifndef __va_copy
#define __va_copy(dest, src) ((void)((dest) = (src)))
#endif

#define VA_COPY(dest, start) __va_copy(dest, start)

#elif defined(_M_arm) || defined(_M_arm64)

/* MSFT arm variable argument list support.*/


typedef char *VA_LIST;

#define VA_START(marker, parameter)                                            \
    __va_start(&marker, &parameter, _INT_SIZE_OF(parameter),               \
           __alignof(parameter), &parameter)
#define VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _INT_SIZE_OF(TYPE) +                             \
                  ((-(intn)marker) & (sizeof(TYPE) - 1))) -        \
           _INT_SIZE_OF(TYPE)))
#define VA_END(marker) (marker = (VA_LIST)0)
#define VA_COPY(dest, start) ((void)((dest) = (start)))

#elif defined(__GNUC__) || defined(__clang__)


/* Use GCC built-in macros for variable argument lists.*/



/* Variable used to traverse the list of arguments. This type can vary by*/
/* implementation and could be an array or structure.*/

typedef __builtin_va_list VA_LIST;

#define VA_START(marker, parameter) __builtin_va_start(marker, parameter)

#define VA_ARG(marker, TYPE)                                                   \
    ((sizeof(TYPE) < sizeof(uintn)) ?                                      \
         (TYPE)(__builtin_va_arg(marker, uintn)) :                     \
         (TYPE)(__builtin_va_arg(marker, TYPE)))

#define VA_END(marker) __builtin_va_end(marker)

#define VA_COPY(dest, start) __builtin_va_copy(dest, start)

#else

/* Variable used to traverse the list of arguments. This type can vary by*/
/* implementation and could be an array or structure.*/

typedef char *VA_LIST;

/**
  Retrieves a pointer to the beginning of a variable argument list, based on
  the name of the parameter that immediately precedes the variable argument list.

  This function initializes marker to point to the beginning of the variable
  argument list that immediately follows parameter.  The method for computing the
  pointer to the next argument in the argument list is CPU-specific following the
  EFIAPI ABI.

  @param   marker       The VA_LIST used to traverse the list of arguments.
  @param   parameter    The name of the parameter that immediately precedes
                        the variable argument list.

  @return  A pointer to the beginning of a variable argument list.

**/
#define VA_START(marker, parameter)                                            \
    (marker = (VA_LIST)((uintn) & (parameter) + _INT_SIZE_OF(parameter)))

/**
  Returns an argument of a specified type from a variable argument list and updates
  the pointer to the variable argument list to point to the next argument.

  This function returns an argument of the type specified by TYPE from the beginning
  of the variable argument list specified by marker.  marker is then updated to point
  to the next argument in the variable argument list.  The method for computing the
  pointer to the next argument in the argument list is CPU-specific following the EFIAPI ABI.

  @param   marker   VA_LIST used to traverse the list of arguments.
  @param   TYPE     The type of argument to retrieve from the beginning
                    of the variable argument list.

  @return  An argument of the type specified by TYPE.

**/
#define VA_ARG(marker, TYPE)                                                   \
    (*(TYPE *)((marker += _INT_SIZE_OF(TYPE)) - _INT_SIZE_OF(TYPE)))

/**
  Terminates the use of a variable argument list.

  This function initializes marker so it can no longer be used with VA_ARG().
  After this macro is used, the only way to access the variable argument list is
  by using VA_START() again.

  @param   marker   VA_LIST used to traverse the list of arguments.

**/
#define VA_END(marker) (marker = (VA_LIST)0)

/**
  Initializes a VA_LIST as a copy of an existing VA_LIST.

  This macro initializes dest as a copy of start, as if the VA_START macro had been applied to dest
  followed by the same sequence of uses of the VA_ARG macro as had previously been used to reach
  the present state of start.

  @param   dest   VA_LIST used to traverse the list of arguments.
  @param   start  VA_LIST used to traverse the list of arguments.

**/
#define VA_COPY(dest, start) ((void)((dest) = (start)))

#endif


/* Pointer to the start of a variable argument list stored in a memory buffer. Same as uint8_t *.*/

typedef uintn *BASE_LIST;

/**
  Returns the size of a data type in sizeof(uintn) units rounded up to the nearest uintn boundary.

  @param  TYPE  The date type to determine the size of.

  @return The size of TYPE in sizeof (uintn) units rounded up to the nearest uintn boundary.
**/
#define _BASE_INT_SIZE_OF(TYPE)                                                \
    ((sizeof(TYPE) + sizeof(uintn) - 1) / sizeof(uintn))

/**
  Returns an argument of a specified type from a variable argument list and updates
  the pointer to the variable argument list to point to the next argument.

  This function returns an argument of the type specified by TYPE from the beginning
  of the variable argument list specified by marker.  marker is then updated to point
  to the next argument in the variable argument list.  The method for computing the
  pointer to the next argument in the argument list is CPU specific following the EFIAPI ABI.

  @param   marker   The pointer to the beginning of a variable argument list.
  @param   TYPE     The type of argument to retrieve from the beginning
                    of the variable argument list.

  @return  An argument of the type specified by TYPE.

**/
#define BASE_ARG(marker, TYPE)                                                 \
    (*(TYPE *)((marker += _BASE_INT_SIZE_OF(TYPE)) -                       \
           _BASE_INT_SIZE_OF(TYPE)))

/**
  The macro that returns the byte offset of a field in a data structure.

  This function returns the offset, in bytes, of field specified by Field from the
  beginning of the  data structure specified by TYPE. If TYPE does not contain Field,
  the module will not compile.

  @param   TYPE     The name of the data structure that contains the field specified by Field.
  @param   field    The name of the field in the data structure.

  @return  offset, in bytes, of field.

**/
#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#define OFFSET_OF(TYPE, field) ((uintn) __builtin_offsetof(TYPE, field))
#endif

#ifndef OFFSET_OF
#define OFFSET_OF(TYPE, field) ((uintn) & (((TYPE *)0)->field))
#endif

/**
  Portable definition for compile time assertions.
  Equivalent to C11 static_assert macro from assert.h.

  @param  expression  Boolean expression.
  @param  message     Raised compiler diagnostic message when expression is false.

**/
#if defined(MDE_CPU_EBC) || defined(CBMC_CC)
#define STATIC_ASSERT(expression, message)
#elif _MSC_EXTENSIONS
#define STATIC_ASSERT static_assert
#else
#define STATIC_ASSERT _Static_assert
#endif


/* Verify that processor_bind.h produced data Types*/


STATIC_ASSERT(
    sizeof(boolean) == 1,
    "sizeof (boolean) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(int8_t) == 1,
    "sizeof (int8_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(uint8_t) == 1,
    "sizeof (uint8_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(int16_t) == 2,
    "sizeof (int16_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(uint16_t) == 2,
    "sizeof (uint16_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(int32_t) == 4,
    "sizeof (int32_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(uint32_t) == 4,
    "sizeof (uint32_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(int64_t) == 8,
    "sizeof (int64_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(uint64_t) == 8,
    "sizeof (uint64_t) does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(char) == 1,
    "sizeof (char) does not meet data Type requirements");


/* The following three enum types are used to verify that the compiler*/
/* configuration for enum types. These enum types and enum values are not*/
/* intended to be used. A prefix of '__' is used avoid conflicts with*/
/* other types.*/

typedef enum { __VerifyUint8EnumValue = 0xff } __VERIFY_UINT8_ENUM_SIZE;

typedef enum { __VerifyUint16EnumValue = 0xffff } __VERIFY_UINT16_ENUM_SIZE;

typedef enum { __VerifyUint32EnumValue = 0xffffffff } __VERIFY_UINT32_ENUM_SIZE;

STATIC_ASSERT(
    sizeof(__VERIFY_UINT8_ENUM_SIZE) == 4,
    "size of enum does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(__VERIFY_UINT16_ENUM_SIZE) == 4,
    "size of enum does not meet data Type requirements");
STATIC_ASSERT(
    sizeof(__VERIFY_UINT32_ENUM_SIZE) == 4,
    "size of enum does not meet data Type requirements");

/**
  Macro that returns a pointer to the data structure that contains a specified field of
  that data structure.  This is a lightweight method to hide information by placing a
  public data structure inside a larger private data structure and using a pointer to
  the public data structure to retrieve a pointer to the private data structure.

  This function computes the offset, in bytes, of field specified by Field from the beginning
  of the  data structure specified by TYPE.  This offset is subtracted from Record, and is
  used to return a pointer to a data structure of the type specified by TYPE. If the data type
  specified by TYPE does not contain the field specified by Field, then the module will not compile.

  @param   record   Pointer to the field specified by Field within a data structure of type TYPE.
  @param   TYPE     The name of the data structure type to return.  This data structure must
                    contain the field specified by Field.
  @param   field    The name of the field in the data structure specified by TYPE to which Record points.

  @return  A pointer to the structure from one of it's elements.

**/
#define BASE_CR(record, TYPE, field)                                           \
    ((TYPE *)((char *)(record)-OFFSET_OF(TYPE, field)))

/**
  Rounds a value up to the next boundary using a specified alignment.

  This function rounds value up to the next boundary using the specified alignment.
  This aligned value is returned.

  @param   value      The value to round up.
  @param   alignment  The alignment boundary used to return the aligned value.

  @return  A value up to the next boundary.

**/
#define ALIGN_VALUE(value, alignment)                                          \
    ((value) + (((alignment) - (value)) & ((alignment)-1)))

/**
  Adjust a pointer by adding the minimum offset required for it to be aligned on
  a specified alignment boundary.

  This function rounds the pointer specified by Pointer to the next alignment boundary
  specified by alignment. The pointer to the aligned address is returned.

  @param   pointer    The pointer to round up.
  @param   alignment  The alignment boundary to use to return an aligned pointer.

  @return  Pointer to the aligned address.

**/
#define ALIGN_POINTER(pointer, alignment)                                      \
    ((void *)(ALIGN_VALUE((uintn)(pointer), (alignment))))

/**
  Rounds a value up to the next natural boundary for the current CPU.
  This is 4-bytes for 32-bit CPUs and 8-bytes for 64-bit CPUs.

  This function rounds the value specified by value up to the next natural boundary for the
  current CPU. This rounded value is returned.

  @param   value      The value to round up.

  @return  Rounded value specified by value.

**/
#define ALIGN_VARIABLE(value) ALIGN_VALUE((value), sizeof(uintn))

/**
  Return the maximum of two operands.

  This macro returns the maximum of two operand specified by a and b.
  Both a and b must be the same numerical types, signed or unsigned.

  @param   a        The first operand with any numerical type.
  @param   b        The second operand. Can be any numerical type as long as is
                    the same type as a.

  @return  Maximum of two operands.

**/
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/**
  Return the minimum of two operands.

  This macro returns the minimal of two operand specified by a and b.
  Both a and b must be the same numerical types, signed or unsigned.

  @param   a        The first operand with any numerical type.
  @param   b        The second operand. It should be the same any numerical type with a.

  @return  Minimum of two operands.

**/
#define MIN(a, b) (((a) < (b)) ? (a) : (b))


/* status codes common to all execution phases*/

typedef uintn return_status;

/**
  Produces a return_status code with the highest bit set.

  @param  status_code    The status code value to convert into a warning code.
                        status_code must be in the range 0x00000000..0x7FFFFFFF.

  @return The value specified by status_code with the highest bit set.

**/
#define ENCODE_ERROR(status_code) ((return_status)(MAX_BIT | (status_code)))

/**
  Produces a return_status code with the highest bit clear.

  @param  status_code    The status code value to convert into a warning code.
                        status_code must be in the range 0x00000000..0x7FFFFFFF.

  @return The value specified by status_code with the highest bit clear.

**/
#define ENCODE_WARNING(status_code) ((return_status)(status_code))

/**
  Returns TRUE if a specified return_status code is an error code.

  This function returns TRUE if status_code has the high bit set.  Otherwise, FALSE is returned.

  @param  status_code    The status code value to evaluate.

  @retval TRUE          The high bit of status_code is set.
  @retval FALSE         The high bit of status_code is clear.

**/
#define RETURN_ERROR(status_code) (((intn)(return_status)(status_code)) < 0)


/* The operation completed successfully.*/

#define RETURN_SUCCESS 0


/* The image failed to load.*/

#define RETURN_LOAD_ERROR ENCODE_ERROR(1)


/* The parameter was incorrect.*/

#define RETURN_INVALID_PARAMETER ENCODE_ERROR(2)


/* The operation is not supported.*/

#define RETURN_UNSUPPORTED ENCODE_ERROR(3)


/* The buffer was not the proper size for the request.*/

#define RETURN_BAD_BUFFER_SIZE ENCODE_ERROR(4)


/* The buffer was not large enough to hold the requested data.*/
/* The required buffer size is returned in the appropriate*/
/* parameter when this error occurs.*/

#define RETURN_BUFFER_TOO_SMALL ENCODE_ERROR(5)


/* There is no data pending upon return.*/

#define RETURN_NOT_READY ENCODE_ERROR(6)


/* The physical device reported an error while attempting the*/
/* operation.*/

#define RETURN_DEVICE_ERROR ENCODE_ERROR(7)


/* The device can not be written to.*/

#define RETURN_WRITE_PROTECTED ENCODE_ERROR(8)


/* The resource has run out.*/

#define RETURN_OUT_OF_RESOURCES ENCODE_ERROR(9)


/* An inconsistency was detected on the file system causing the*/
/* operation to fail.*/

#define RETURN_VOLUME_CORRUPTED ENCODE_ERROR(10)


/* There is no more space on the file system.*/

#define RETURN_VOLUME_FULL ENCODE_ERROR(11)


/* The device does not contain any medium to perform the*/
/* operation.*/

#define RETURN_NO_MEDIA ENCODE_ERROR(12)


/* The medium in the device has changed since the last*/
/* access.*/

#define RETURN_MEDIA_CHANGED ENCODE_ERROR(13)


/* The item was not found.*/

#define RETURN_NOT_FOUND ENCODE_ERROR(14)


/* Access was denied.*/

#define RETURN_ACCESS_DENIED ENCODE_ERROR(15)


/* The server was not found or did not respond to the request.*/

#define RETURN_NO_RESPONSE ENCODE_ERROR(16)


/* A mapping to the device does not exist.*/

#define RETURN_NO_MAPPING ENCODE_ERROR(17)


/* A timeout time expired.*/

#define RETURN_TIMEOUT ENCODE_ERROR(18)


/* The protocol has not been started.*/

#define RETURN_NOT_STARTED ENCODE_ERROR(19)


/* The protocol has already been started.*/

#define RETURN_ALREADY_STARTED ENCODE_ERROR(20)


/* The operation was aborted.*/

#define RETURN_ABORTED ENCODE_ERROR(21)


/* An ICMP error occurred during the network operation.*/

#define RETURN_ICMP_ERROR ENCODE_ERROR(22)


/* A TFTP error occurred during the network operation.*/

#define RETURN_TFTP_ERROR ENCODE_ERROR(23)


/* A protocol error occurred during the network operation.*/

#define RETURN_PROTOCOL_ERROR ENCODE_ERROR(24)


/* A function encountered an internal version that was*/
/* incompatible with a version requested by the caller.*/

#define RETURN_INCOMPATIBLE_VERSION ENCODE_ERROR(25)


/* The function was not performed due to a security violation.*/

#define RETURN_SECURITY_VIOLATION ENCODE_ERROR(26)


/* A CRC error was detected.*/

#define RETURN_CRC_ERROR ENCODE_ERROR(27)


/* The beginning or end of media was reached.*/

#define RETURN_END_OF_MEDIA ENCODE_ERROR(28)


/* The end of the file was reached.*/

#define RETURN_END_OF_FILE ENCODE_ERROR(31)


/* The language specified was invalid.*/

#define RETURN_INVALID_LANGUAGE ENCODE_ERROR(32)


/* The security status of the data is unknown or compromised*/
/* and the data must be updated or replaced to restore a valid*/
/* security status.*/

#define RETURN_COMPROMISED_DATA ENCODE_ERROR(33)


/* A HTTP error occurred during the network operation.*/

#define RETURN_HTTP_ERROR ENCODE_ERROR(35)


/* The string contained one or more characters that*/
/* the device could not render and were skipped.*/

#define RETURN_WARN_UNKNOWN_GLYPH ENCODE_WARNING(1)


/* The handle was closed, but the file was not deleted.*/

#define RETURN_WARN_DELETE_FAILURE ENCODE_WARNING(2)


/* The handle was closed, but the data to the file was not*/
/* flushed properly.*/

#define RETURN_WARN_WRITE_FAILURE ENCODE_WARNING(3)


/* The resulting buffer was too small, and the data was*/
/* truncated to the buffer size.*/

#define RETURN_WARN_BUFFER_TOO_SMALL ENCODE_WARNING(4)


/* The data has not been updated within the timeframe set by*/
/* local policy for this type of data.*/

#define RETURN_WARN_STALE_DATA ENCODE_WARNING(5)


/* The resulting buffer contains file system.*/

#define RETURN_WARN_FILE_SYSTEM ENCODE_WARNING(6)

/**
  Returns a 16-bit signature built from 2 ASCII characters.

  This macro returns a 16-bit value built from the two ASCII characters specified
  by A and B.

  @param  A    The first ASCII character.
  @param  B    The second ASCII character.

  @return A 16-bit value built from the two ASCII characters specified by A and B.

**/
#define SIGNATURE_16(A, B) ((A) | (B << 8))

/**
  Returns a 32-bit signature built from 4 ASCII characters.

  This macro returns a 32-bit value built from the four ASCII characters specified
  by A, B, C, and D.

  @param  A    The first ASCII character.
  @param  B    The second ASCII character.
  @param  C    The third ASCII character.
  @param  D    The fourth ASCII character.

  @return A 32-bit value built from the two ASCII characters specified by A, B,
          C and D.

**/
#define SIGNATURE_32(A, B, C, D)                                               \
    (SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

/**
  Returns a 64-bit signature built from 8 ASCII characters.

  This macro returns a 64-bit value built from the eight ASCII characters specified
  by A, B, C, D, E, F, G,and H.

  @param  A    The first ASCII character.
  @param  B    The second ASCII character.
  @param  C    The third ASCII character.
  @param  D    The fourth ASCII character.
  @param  E    The fifth ASCII character.
  @param  F    The sixth ASCII character.
  @param  G    The seventh ASCII character.
  @param  H    The eighth ASCII character.

  @return A 64-bit value built from the two ASCII characters specified by A, B,
          C, D, E, F, G and H.

**/
#define SIGNATURE_64(A, B, C, D, E, F, G, H)                                   \
    (SIGNATURE_32(A, B, C, D) | ((uint64_t)(SIGNATURE_32(E, F, G, H)) << 32))

#if defined(_MSC_EXTENSIONS) && !defined(__INTEL_COMPILER) &&                  \
    !defined(MDE_CPU_EBC)
void *_ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)
/**
    Get the return address of the calling function.

    Based on intrinsic function _ReturnAddress that provides the address of
    the instruction in the calling function that will be executed after
    control returns to the caller.

    @param L    Return Level.

    @return The return address of the calling function or 0 if L != 0.

  **/
#define RETURN_ADDRESS(L) ((L == 0) ? _ReturnAddress() : (void *)0)
#elif defined(__GNUC__) || defined(__clang__)
void *__builtin_return_address(unsigned int level);
/**
    Get the return address of the calling function.

    Based on built-in Function __builtin_return_address that returns
    the return address of the current function, or of one of its callers.

    @param L    Return Level.

    @return The return address of the calling function.

  **/
#define RETURN_ADDRESS(L) __builtin_return_address(L)
#else
/**
    Get the return address of the calling function.

    @param L    Return Level.

    @return 0 as compilers don't support this feature.

  **/
#define RETURN_ADDRESS(L) ((void *)0)
#endif

/**
  Return the number of elements in an array.

  @param  array  An object of array type. Array is only used as an argument to
                 the sizeof operator, therefore Array is never evaluated. The
                 caller is responsible for ensuring that Array's type is not
                 incomplete; that is, Array must have known constant size.

  @return The number of elements in Array. The result has type uintn.

**/
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#endif
