/**
 * Copyright Notice:
 * Copyright 2022 DMTF. All rights reserved.
 * License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in milliseconds.
 *
 **/
void libspdm_sleep_in_us(uint64_t microseconds)
{
    uint64_t milliseconds;

    milliseconds = (microseconds + 1000 - 1) / 1000;
    Sleep((DWORD)milliseconds);
}
