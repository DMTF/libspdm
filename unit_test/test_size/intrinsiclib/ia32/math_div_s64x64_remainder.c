/** @file
  64-bit Math Worker Function.
  The 32-bit versions of C compiler generate calls to library routines
  to handle 64-bit math. These functions use non-standard calling conventions.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

uint64 InternalMathDivRemU64x64(IN uint64 Dividend, IN uint64 Divisor,
				OUT uint64 *Remainder OPTIONAL);

int64 InternalMathDivRemS64x64(IN int64 Dividend, IN int64 Divisor,
			       OUT int64 *Remainder OPTIONAL)
{
	int64 Quot;

	Quot = InternalMathDivRemU64x64(
		(uint64)(Dividend >= 0 ? Dividend : -Dividend),
		(uint64)(Divisor >= 0 ? Divisor : -Divisor),
		(uint64 *)Remainder);
	if (Remainder != NULL && Dividend < 0) {
		*Remainder = -*Remainder;
	}
	return (Dividend ^ Divisor) >= 0 ? Quot : -Quot;
}

int64 DivS64x64Remainder(IN int64 Dividend, IN int64 Divisor,
			 OUT int64 *Remainder OPTIONAL)
{
	return InternalMathDivRemS64x64(Dividend, Divisor, Remainder);
}

/*
 * Divides a 64-bit signed value with a 64-bit signed value and returns
 * a 64-bit signed result and 64-bit signed remainder.
 */
__declspec(naked) void __cdecl _alldvrm(void)
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

    ; Original local stack when calling _alldvrm
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
    ; Put the Reminder in EBX:ECX as return value
    ;
    mov  ecx, [esp + 20]
    mov  ebx, [esp + 24]

    ;
    ; Adjust stack
    ;
    add  esp, 28

    ret  16
  }
}
