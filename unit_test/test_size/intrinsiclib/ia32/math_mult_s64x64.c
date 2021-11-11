/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <hal/base.h>

uint64 internal_math_mult_u64x64(IN uint64 multiplicand, IN uint64 multiplier)
{
	_asm {
    mov     ebx, dword ptr [multiplicand + 0]
    mov     edx, dword ptr [multiplier + 0]
    mov     ecx, ebx
    mov     eax, edx
    imul    ebx, dword ptr [multiplier + 4]
    imul    edx, dword ptr [multiplicand + 4]
    add     ebx, edx
    mul     ecx
    add     edx, ebx
	}
}

uint64 mult_u64x64(IN uint64 multiplicand, IN uint64 multiplier)
{
	uint64 result;

	result = internal_math_mult_u64x64(multiplicand, multiplier);

	return result;
}

int64 mult_s64x64(IN int64 multiplicand, IN int64 multiplier)
{
	return (int64)mult_u64x64((uint64)multiplicand, (uint64)multiplier);
}

/*
 * Multiplies a 64-bit signed or unsigned value by a 64-bit signed or unsigned value
 * and returns a 64-bit result.
 */
__declspec(naked) void __cdecl _allmul(void)
{
	//
	//    int64
	//      //    mult_s64x64 (
	//      IN      int64      multiplicand,
	//      IN      int64      multiplier
	//      )
	//
  _asm {
    ; Original local stack when calling _allmul
    ;               -----------------
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--multiplier --|
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--multiplicand-|
    ;               |               |
    ;               |---------------|
    ;               |  ReturnAddr** |
    ;       ESP---->|---------------|
    ;

    ;
    ; Set up the local stack for multiplicand parameter
    ;
    mov  eax, [esp + 16]
    push eax
    mov  eax, [esp + 16]
    push eax

    ;
    ; Set up the local stack for multiplier parameter
    ;
    mov  eax, [esp + 16]
    push eax
    mov  eax, [esp + 16]
    push eax

    ;
    ; Call native MulS64x64 of BaseLib
    ;
    call mult_s64x64

    ;
    ; Adjust stack
    ;
    add  esp, 16

    ret  16
  }
}
