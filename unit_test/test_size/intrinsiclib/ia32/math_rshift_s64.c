/** @file
  64-bit Math Worker Function.
  The 32-bit versions of C compiler generate calls to library routines
  to handle 64-bit math. These functions use non-standard calling conventions.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/*
 * Shifts a 64-bit signed value right by a certain number of bits.
 */
__declspec(naked) void __cdecl _allshr(void)
{
	_asm {
    ;
    ; Checking: Only handle 64bit shifting or more
    ;
    cmp     cl, 64
    jae     _Exit

    ;
    ; Handle shifting between 0 and 31 bits
    ;
    cmp     cl, 32
    jae     More32
    shrd    eax, edx, cl
    sar     edx, cl
    ret

    ;
    ; Handle shifting of 32-63 bits
    ;
More32:
    mov     eax, edx
    sar     edx, 31
    and     cl, 31
    sar     eax, cl
    ret

    ;
    ; Return 0 or -1, depending on the sign of edx
    ;
done:
    sar     edx, 31
    mov     eax, edx
    ret
	}
}
