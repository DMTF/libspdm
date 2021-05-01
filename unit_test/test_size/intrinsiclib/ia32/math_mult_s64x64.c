/** @file
  64-bit Math Worker Function.
  The 32-bit versions of C compiler generate calls to library routines
  to handle 64-bit math. These functions use non-standard calling conventions.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

uint64 InternalMathMultU64x64(IN uint64 Multiplicand, IN uint64 Multiplier)
{
	_asm {
    mov     ebx, dword ptr [Multiplicand + 0]
    mov     edx, dword ptr [Multiplier + 0]
    mov     ecx, ebx
    mov     eax, edx
    imul    ebx, dword ptr [Multiplier + 4]
    imul    edx, dword ptr [Multiplicand + 4]
    add     ebx, edx
    mul     ecx
    add     edx, ebx
	}
}

uint64 MultU64x64(IN uint64 Multiplicand, IN uint64 Multiplier)
{
	uint64 result;

	result = InternalMathMultU64x64(Multiplicand, Multiplier);

	return result;
}

int64 MultS64x64(IN int64 Multiplicand, IN int64 Multiplier)
{
	return (int64)MultU64x64((uint64)Multiplicand, (uint64)Multiplier);
}

/*
 * Multiplies a 64-bit signed or unsigned value by a 64-bit signed or unsigned value
 * and returns a 64-bit result.
 */
__declspec(naked) void __cdecl _allmul(void)
{
	//
	// Wrapper Implementation over EDKII MultS64x64() routine
	//    int64
	//      //    MultS64x64 (
	//      IN      int64      Multiplicand,
	//      IN      int64      Multiplier
	//      )
	//
  _asm {
    ; Original local stack when calling _allmul
    ;               -----------------
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--Multiplier --|
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--Multiplicand-|
    ;               |               |
    ;               |---------------|
    ;               |  ReturnAddr** |
    ;       ESP---->|---------------|
    ;

    ;
    ; Set up the local stack for Multiplicand parameter
    ;
    mov  eax, [esp + 16]
    push eax
    mov  eax, [esp + 16]
    push eax

    ;
    ; Set up the local stack for Multiplier parameter
    ;
    mov  eax, [esp + 16]
    push eax
    mov  eax, [esp + 16]
    push eax

    ;
    ; Call native MulS64x64 of BaseLib
    ;
    call MultS64x64

    ;
    ; Adjust stack
    ;
    add  esp, 16

    ret  16
  }
}
