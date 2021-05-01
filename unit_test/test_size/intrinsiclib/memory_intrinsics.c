/** @file
  Intrinsic Memory Routines Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>
#include <library/memlib.h>

typedef uintn size_t;

#if defined(__GNUC__) || defined(__clang__)
#define GLOBAL_USED __attribute__((used))
#else
#define GLOBAL_USED
#endif

/* OpenSSL will use floating point support, and C compiler produces the _fltused
   symbol by default. Simply define this symbol here to satisfy the linker. */
int GLOBAL_USED _fltused = 1;

/* Sets buffers to a specified character */
void *memset(void *dest, int ch, size_t count)
{
	//
	// NOTE: Here we use one base implementation for memset, instead of the direct
	//       optimized set_mem() wrapper. Because the intrinsiclib has to be built
	//       without whole program optimization option, and there will be some
	//       potential register usage errors when calling other optimized codes.
	//

	//
	// Declare the local variables that actually move the data elements as
	// volatile to prevent the optimizer from replacing this function with
	// the intrinsic memset()
	//
	volatile uint8 *Pointer;

	Pointer = (uint8 *)dest;
	while (count-- != 0) {
		*(Pointer++) = (uint8)ch;
	}

	return dest;
}

void *memmove(void *dest, const void *src, size_t count)
{
	copy_mem(dest, src, count);
	return dest;
}

/* Compare bytes in two buffers. */
int memcmp(const void *buf1, const void *buf2, size_t count)
{
	return (int)compare_mem(buf1, buf2, count);
}

intn AsciiStrCmp(IN const char8 *FirstString, IN const char8 *SecondString)
{
	while ((*FirstString != '\0') && (*FirstString == *SecondString)) {
		FirstString++;
		SecondString++;
	}

	return *FirstString - *SecondString;
}

int strcmp(const char *s1, const char *s2)
{
	return (int)AsciiStrCmp(s1, s2);
}

uintn ascii_str_len(IN const char8 *string)
{
	uintn length;

	if (string == NULL) {
		return 0;
	}
	for (length = 0; *string != '\0'; string++, length++) {
	}
	return length;
}

unsigned int strlen(char *s)
{
	return (unsigned int)ascii_str_len(s);
}

char8 *AsciiStrStr(IN const char8 *string, IN const char8 *SearchString)
{
	const char8 *FirstMatch;
	const char8 *SearchStringTmp;

	if (*SearchString == '\0') {
		return (char8 *)string;
	}

	while (*string != '\0') {
		SearchStringTmp = SearchString;
		FirstMatch = string;

		while ((*string == *SearchStringTmp) && (*string != '\0')) {
			string++;
			SearchStringTmp++;
		}

		if (*SearchStringTmp == '\0') {
			return (char8 *)FirstMatch;
		}

		if (*string == '\0') {
			return NULL;
		}

		string = FirstMatch + 1;
	}

	return NULL;
}

char *strstr(char *str1, const char *str2)
{
	return AsciiStrStr(str1, str2);
}
