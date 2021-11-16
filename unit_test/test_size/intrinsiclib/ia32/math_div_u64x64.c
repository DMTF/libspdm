/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <hal/base.h>

uint64_t div_u64x64_remainder(IN uint64_t dividend, IN uint64_t divisor,
			  OUT uint64_t *remainder OPTIONAL);

/*
 * Divides a 64-bit unsigned value with a 64-bit unsigned value and returns
 * a 64-bit unsigned result.
 */
__declspec(naked) void __cdecl _aulldiv(void)
{
	//
	//    uint64_t
	//      //    div_u64x64_remainder (
	//      IN      uint64_t     dividend,
	//      IN      uint64_t     divisor,
	//      OUT     uint64_t     *remainder  OPTIONAL
	//      )
	//
  _asm {

    ; Original local stack when calling _aulldiv
    ;               -----------------
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  divisor  --|
    ;               |               |
    ;               |---------------|
    ;               |               |
    ;               |--  dividend --|
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
    ; Set up the local stack for divisor parameter
    ;
    mov  eax, [esp + 20]
    push eax
    mov  eax, [esp + 20]
    push eax

    ;
    ; Set up the local stack for dividend parameter
    ;
    mov  eax, [esp + 20]
    push eax
    mov  eax, [esp + 20]
    push eax

    ;
    ; Call native div_u64x64_remainder of BaseLib
    ;
    call div_u64x64_remainder

    ;
    ; Adjust stack
    ;
    add  esp, 20

    ret  16
  }
}
