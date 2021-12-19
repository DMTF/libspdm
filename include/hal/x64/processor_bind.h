/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_X64


/* Make sure we are using the correct packing rules per EFI specification*/

#if !defined(__GNUC__)
#pragma pack()
#endif

#if defined(__GNUC__) && defined(__pic__) && !defined(USING_LTO) &&            \
    !defined(__APPLE__)

/* Mark all symbol declarations and references as hidden, meaning they will*/
/* not be subject to symbol preemption. This allows the compiler to refer to*/
/* symbols directly using relative references rather than via the GOT, which*/
/* contains absolute symbol addresses that are subject to runtime relocation.*/

/* The LTO linker will not emit GOT based relocations when all symbol*/
/* references can be resolved locally, and so there is no need to set the*/
/* pragma in that case (and doing so will cause other issues).*/

#pragma GCC visibility push(hidden)
#endif

#if defined(_MSC_EXTENSIONS)


/* Disable warning that make it impossible to compile at /W4*/
/* This only works for Microsoft* tools*/



/* Disabling bitfield type checking warnings.*/

#pragma warning(disable : 4214)


/* Disabling the unreferenced formal parameter warnings.*/

#pragma warning(disable : 4100)


/* Disable slightly different base types warning as char8 * can not be set*/
/* to a constant string.*/

#pragma warning(disable : 4057)


/* ASSERT(FALSE) or while (TRUE) are legal constructs so suppress this warning*/

#pragma warning(disable : 4127)


/* This warning is caused by functions defined but not used. For precompiled header only.*/

#pragma warning(disable : 4505)


/* This warning is caused by empty (after preprocessing) source file. For precompiled header only.*/

#pragma warning(disable : 4206)

#if _MSC_VER == 1800 || _MSC_VER == 1900 || _MSC_VER >= 1910


/* Disable these warnings for VS2013.*/



/* This warning is for potentially uninitialized local variable, and it may cause false*/
/* positive issues in VS2013 and VS2015 build*/

#pragma warning(disable : 4701)


/* This warning is for potentially uninitialized local pointer variable, and it may cause*/
/* false positive issues in VS2013 and VS2015 build*/

#pragma warning(disable : 4703)

#endif

#endif

#ifndef LIBSPDM_STDINT_ALT

#include <stdint.h>

/* LIBSPDM_OPENSSL_STDINT_WORKAROUND*/

/* This is a workaround for OpenSSL compilation problems when used with <stdint.h>*/
/* on Windows platforms built with Visual Studio. Including <stdint.h> pulls in*/
/* <vcruntime.h>, which causes the type size_t to be defined. The size_t type*/
/* depends on if _WIN32 or _WIN64 is defined. The default if neither is defined*/
/* is the 32-bit version of size_t.*/

/* Our OpenSSL compilation requires _WIN32 and _WIN64 to NOT be defined.*/
/* This will force the <vcruntime.h> to use the wrong 32-bit definition of size_t*/
/* if we are compiling as 64-bit. This 32-bit definition then does not agree with*/
/* the 64-bit definition defined in libspdm and generates compile errors.*/

/* To workaround this issue, LIBSPDM_OPENSSL_STDINT_WORKAROUND was created*/
/* that is only defined for compilation via tha makefile of the OpenSSL library*/
/* portion of libspdm.*/

/* This will lead to _WIN32 and _WIN64 to be NOT defined when reaching the OpenSSL*/
/* portions of a compilation unit (header files + c file), thus meeting the*/
/* no Win32/Win64 requirement for OpenSSL, but will still be defined when compiling*/
/* the <vcruntime.h> file in the compilation unit (and getting the right size_t).*/

/* In the future libspdm intends to use the Windows native compilation flags and defines,*/
/* in place of the UEFI profile / personality.*/

#ifdef LIBSPDM_OPENSSL_STDINT_WORKAROUND
#undef _WIN32
#undef _WIN64
#endif

#else
#include LIBSPDM_STDINT_ALT
#endif

typedef char char8;
typedef unsigned char boolean;


/* Unsigned value of native width.  (4 bytes on supported 32-bit processor instructions,*/
/* 8 bytes on supported 64-bit processor instructions)*/

typedef uint64_t uintn;

/* Signed value of native width.  (4 bytes on supported 32-bit processor instructions,*/
/* 8 bytes on supported 64-bit processor instructions)*/

typedef int64_t intn;


/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x8000000000000000ULL


/* Maximum legal x64 address*/

#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL


/* Maximum legal x64 intn values.*/

#define MAX_INTN ((intn)0x7FFFFFFFFFFFFFFFULL)

#endif
