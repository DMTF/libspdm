/**
 * Copyright Notice:
 * Copyright 2022 DMTF. All rights reserved.
 * License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param milliseconds     The time interval for which execution is to be suspended, in milliseconds.
 *
 **/
void libspdm_sleep(IN uint64_t milliseconds)
{
    struct timeval tv;
    int err;

    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds % 1000) * 1000;

    do {
        err=select(0, NULL, NULL, NULL, &tv);
    } while(err<0 && errno==EINTR);
}
