/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

/*
 * Floating point to integer conversion.
 */
__declspec(naked) void _ftol2(void)
{
    _asm {
        fistp qword ptr [esp-8]
        mov edx, [esp-4]
        mov eax, [esp-8]
        ret
    }
}
