/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Provides random number generator services.
**/

#ifndef __SLEEP_LIB_H__
#define __SLEEP_LIB_H__

/**
  Suspends the execution of the current thread until the time-out interval elapses.

  @param[in] milliseconds     The time interval for which execution is to be suspended, in milliseconds.

**/
void libspdm_sleep(uint64_t milliseconds);

#endif // __SLEEP_LIB_H__
