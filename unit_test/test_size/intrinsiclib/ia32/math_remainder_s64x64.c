/** @file
  64-bit Math Worker Function.
  The 32-bit versions of C compiler generate calls to library routines
  to handle 64-bit math. These functions use non-standard calling conventions.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

int64 DivS64x64Remainder(IN int64 Dividend, IN int64 Divisor,
			 OUT int64 *Remainder OPTIONAL);

/*
 * Divides a 64-bit signed value by another 64-bit signed value and returns
 * the 64-bit signed remainder.
 */
__declspec(naked) void __cdecl _allrem(void)
{
	//
	// Wrapper Implementation over EDKII DivS64x64Remainder() routine
	//    int64
	//      //    DivS64x64Remainder (
	//      IN      int64     Dividend,
	//      IN      int64     Divisor,
	//      OUT     int64     *Remainder  OPTIONAL
	//      )
	//
  _asm {
    ; Original local stack when calling _allrem
    ;               -----------------
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  Divisor  --|
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  Dividend --|
    ;               |               |
    ;               |---------------|
    ;               |  ReturnAddr** |
    ;       ESP---->|---------------|
    ;

    ;
    ; Set up the local stack for Reminder pointer
    ;
    sub  esp, 8
    push esp

    ;
    ; Set up the local stack for Divisor parameter
    ;
    mov  eax, [esp + 28]
    push eax
    mov  eax, [esp + 28]
    push eax

    ;
    ; Set up the local stack for Dividend parameter
    ;
    mov  eax, [esp + 28]
    push eax
    mov  eax, [esp + 28]
    push eax

    ;
    ; Call native DivS64x64Remainder of BaseLib
    ;
    call DivS64x64Remainder

    ;
    ; Put the Reminder in EDX:EAX as return value
    ;
    mov  eax, [esp + 20]
    mov  edx, [esp + 24]

    ;
    ; Adjust stack
    ;
    add  esp, 28

    ret  16
  }
}
