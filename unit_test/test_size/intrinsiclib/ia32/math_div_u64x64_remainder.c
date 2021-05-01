/** @file
  64-bit Math Worker Function.
  The 32-bit versions of C compiler generate calls to library routines
  to handle 64-bit math. These functions use non-standard calling conventions.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

uint64 InternalMathDivRemU64x32(IN uint64 Dividend, IN uint32 Divisor,
				OUT uint32 *Remainder)
{
	_asm {
    mov     ecx, Divisor
    mov     eax, dword ptr [Dividend + 4]
    xor     edx, edx
    div     ecx
    push    eax
    mov     eax, dword ptr [Dividend + 0]
    div     ecx
    mov     ecx, Remainder
    jecxz   RemainderNull // abandon remainder if Remainder == NULL
    mov     [ecx], edx
RemainderNull:
    pop     edx
	}
}

__declspec(naked) uint64
	InternalMathDivRemU64x64(IN uint64 Dividend, IN uint64 Divisor,
				 OUT uint64 *Remainder OPTIONAL)
{
  _asm {
    mov     ecx, [esp + 16]             ; ecx <- divisor[32..63]
    test    ecx, ecx
    jnz     ___DivRemU64x64              ; call _@DivRemU64x64 if Divisor > 2^32
    mov     ecx, [esp + 20]
    jecxz   __0
    and     [ecx + 4], 0      ; zero high dword of remainder
    mov     [esp + 16], ecx             ; set up stack frame to match DivRemU64x32
__0:
    jmp     InternalMathDivRemU64x32

___DivRemU64x64:
    push    ebx
    push    esi
    push    edi
    mov     edx, [esp + 20]
    mov     eax, [esp + 16]   ; edx:eax <- dividend
    mov     edi, edx
    mov     esi, eax                    ; edi:esi <- dividend
    mov     ebx, [esp + 24]   ; ecx:ebx <- divisor
__1:
    shr     edx, 1
    rcr     eax, 1
    shrd    ebx, ecx, 1
    shr     ecx, 1
    jnz     __1
    div     ebx
    mov     ebx, eax                    ; ebx <- quotient
    mov     ecx, [esp + 28]             ; ecx <- high dword of divisor
    mul     [esp + 24]        ; edx:eax <- quotient * divisor[0..31]
    imul    ecx, ebx                    ; ecx <- quotient * divisor[32..63]
    add     edx, ecx                    ; edx <- (quotient * divisor)[32..63]
    mov     ecx, [esp + 32]   ; ecx <- addr for Remainder
    jc      __TooLarge                   ; product > 2^64
    cmp     edi, edx                    ; compare high 32 bits
    ja      __Correct
    jb      __TooLarge                   ; product > dividend
    cmp     esi, eax
    jae     __Correct                    ; product <= dividend
__TooLarge:
    dec     ebx                         ; adjust quotient by -1
    jecxz   __Return                     ; return if Remainder == NULL
    sub     eax, [esp + 24]
    sbb     edx, [esp + 28]   ; edx:eax <- (quotient - 1) * divisor
__Correct:
    jecxz   __Return
    sub     esi, eax
    sbb     edi, edx                    ; edi:esi <- remainder
    mov     [ecx], esi
    mov     [ecx + 4], edi
__Return:
    mov     eax, ebx                    ; eax <- quotient
    xor     edx, edx                    ; quotient is 32 bits long
    pop     edi
    pop     esi
    pop     ebx
    ret
  }
}

uint64 DivU64x64Remainder(IN uint64 Dividend, IN uint64 Divisor,
			  OUT uint64 *Remainder OPTIONAL)
{
	return InternalMathDivRemU64x64(Dividend, Divisor, Remainder);
}

/*
 * Divides a 64-bit unsigned value with a 64-bit unsigned value and returns
 * a 64-bit unsigned result and 64-bit unsigned remainder.
 */
__declspec(naked) void __cdecl _aulldvrm(void)
{
	//
	// Wrapper Implementation over EDKII DivU64x64Reminder() routine
	//    uint64
	//      //    DivU64x64Remainder (
	//      IN      uint64     Dividend,
	//      IN      uint64     Divisor,
	//      OUT     uint64     *Remainder  OPTIONAL
	//      )
	//
  _asm {

    ; Original local stack when calling _aulldvrm
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
    ; Call native DivU64x64Remainder of BaseLib
    ;
    call DivU64x64Remainder

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
