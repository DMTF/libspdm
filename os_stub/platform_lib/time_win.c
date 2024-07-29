/**
 * SPDX-FileCopyrightText: 2022-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

#include <base.h>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in microseconds.
 *
 **/
void libspdm_sleep(uint64_t microseconds)
{
    uint64_t milliseconds;

    /* If 0 is given as the sleep time interval, the thread will relinquish the remainder of its time slice.
     * https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep
     * Return immediately to avoid unexpected re-scheduling. */
    if (microseconds == 0) {
        return;
    }

    milliseconds = (microseconds + 1000 - 1) / 1000;
    Sleep((DWORD)milliseconds);
}
