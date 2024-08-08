/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

/*
 * this is armv8 reference code to implement time_sleep
 * the armv8 special code form https://github.com/altera-opensource/intel-socfpga-hwlib
 **/

#include <base.h>
#include <stdlib.h>
#include <errno.h>
#include "hal/library/debuglib.h"

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in microseconds.
 *
 **/

void libspdm_sleep(uint64_t microseconds)
{
    /*the feature for armclang build is TBD*/
    LIBSPDM_ASSERT(false);
}
