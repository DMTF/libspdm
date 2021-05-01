/** @file
  C Run-Time Libraries (CRT) Time Management Routines Wrapper Implementation
  for OpenSSL-based Cryptographic Library (used in DXE & RUNTIME).

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>
#include <library/memlib.h>
#include <mbedtls/platform_time.h>

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt,
				     struct tm *tm_buf)
{
	struct tm *lt;

	lt = gmtime(tt);

	if (lt != NULL) {
		copy_mem(tm_buf, lt, sizeof(struct tm));
	}

	return ((lt == NULL) ? NULL : tm_buf);
}
