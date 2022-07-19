/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef PROCESSOR_BIND_H
#define PROCESSOR_BIND_H

#define LIBSPDM_CPU_X64

#if defined(_MSC_EXTENSIONS)

/* For Microsoft tools disable warnings that make it impossible to compile at /W4. */

/* Disable unreferenced formal parameter warnings. */
#pragma warning(disable : 4100)

/* Disable slightly different base types warning as char * can not be set
 * to a constant string. */
#pragma warning(disable : 4057)

#if _MSC_VER == 1800 || _MSC_VER == 1900 || _MSC_VER >= 1910
/* Disable these warnings for VS2013.*/

/* This warning is for potentially uninitialized local variable, and it may cause false
 * positive issues in VS2013 and VS2015 build*/
#pragma warning(disable : 4701)

/* This warning is for potentially uninitialized local pointer variable, and it may cause
 * false positive issues in VS2013 and VS2015 build*/
#pragma warning(disable : 4703)

#endif /* _MSC_VER == 1800 || _MSC_VER == 1900 || _MSC_VER >= 1910 */

#endif /* _MSC_EXTENSIONS */

#ifndef LIBSPDM_STDINT_ALT

#include <stdint.h>

/* LIBSPDM_OPENSSL_STDINT_WORKAROUND*/

/* This is a workaround for OpenSSL compilation problems when used with <stdint.h>
 * on Windows platforms built with Visual Studio. Including <stdint.h> pulls in
 * <vcruntime.h>, which causes the type size_t to be defined. The size_t type
 * depends on if _WIN32 or _WIN64 is defined. The default if neither is defined
 * is the 32-bit version of size_t.*/

/* Our OpenSSL compilation requires _WIN32 and _WIN64 to NOT be defined.
 * This will force the <vcruntime.h> to use the wrong 32-bit definition of size_t
 * if we are compiling as 64-bit. This 32-bit definition then does not agree with
 * the 64-bit definition defined in libspdm and generates compile errors.*/

/* To workaround this issue, LIBSPDM_OPENSSL_STDINT_WORKAROUND was created
 * that is only defined for compilation via tha makefile of the OpenSSL library
 * portion of libspdm.*/

/* This will lead to _WIN32 and _WIN64 to be NOT defined when reaching the OpenSSL
* portions of a compilation unit (header files + c file), thus meeting the
* no Win32/Win64 requirement for OpenSSL, but will still be defined when compiling
* the <vcruntime.h> file in the compilation unit (and getting the right size_t).*/

/* In the future libspdm intends to use the Windows native compilation flags and defines,
 * in place of the UEFI profile / personality.*/

#ifdef LIBSPDM_OPENSSL_STDINT_WORKAROUND
#undef _WIN32
#undef _WIN64
#endif /* LIBSPDM_OPENSSL_STDINT_WORKAROUND */

#else
#include LIBSPDM_STDINT_ALT
#endif /* LIBSPDM_STDINT_ALT */

#ifndef LIBSPDM_STDBOOL_ALT
#include <stdbool.h>
#else
#include LIBSPDM_STDBOOL_ALT
#endif /* LIBSPDM_STDBOOL_ALT */

#ifndef LIBSPDM_STDDEF_ALT
#include <stddef.h>
#else
#include LIBSPDM_STDDEF_ALT
#endif /* LIBSPDM_STDDEF_ALT */

#endif /* PROCESSOR_BIND_H */
