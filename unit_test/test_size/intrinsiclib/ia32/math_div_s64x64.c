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
 * Divides a 64-bit signed value with a 64-bit signed value and returns
 * a 64-bit signed result.
 */
__declspec(naked) void __cdecl _alldiv(void)
{
	//
	// Wrapper Implementation over EDKII DivS64x64Reminder() routine
	//    int64
	//      //    DivS64x64Remainder (
	//      IN      int64     Dividend,
	//      IN      int64     Divisor,
	//      OUT     int64     *Remainder  OPTIONAL
	//      )
	//
  _asm {

    ; Original local stack when calling _alldiv
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
    ; Set up the local stack for NULL Reminder pointer
    ;
    xor  eax, eax
    push eax

    ;
    ; Set up the local stack for Divisor parameter
    ;
    mov  eax, [esp + 20]
    push eax
    mov  eax, [esp + 20]
    push eax

    ;
    ; Set up the local stack for Dividend parameter
    ;
    mov  eax, [esp + 20]
    push eax
    mov  eax, [esp + 20]
    push eax

    ;
    ; Call native DivS64x64Remainder of BaseLib
    ;
    call DivS64x64Remainder

    ;
    ; Adjust stack
    ;
    add  esp, 20

    ret  16
  }
}
