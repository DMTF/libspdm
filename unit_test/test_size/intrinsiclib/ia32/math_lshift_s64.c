/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

/*
 * Shifts a 64-bit signed value left by a particular number of bits.
 */
__declspec(naked) void __cdecl _allshl(void)
{
    _asm {
        ;
        ; Handle shifting of 64 or more bits (return 0)
        ;
        cmp cl, 64
        jae     short ReturnZero

        ;
        ; Handle shifting of between 0 and 31 bits
        ;
        cmp cl, 32
        jae     short More32
        shld edx, eax, cl
        shl eax, cl
            ret

        ;
        ; Handle shifting of between 32 and 63 bits
        ;
More32:
        mov edx, eax
        xor eax, eax
        and cl, 31
        shl edx, cl
        ret

ReturnZero:
        xor eax,eax
        xor edx,edx
        ret
    }
}
