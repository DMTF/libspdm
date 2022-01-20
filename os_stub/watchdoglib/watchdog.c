/**
    Copyright Notice:
    Copyright 2022 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include <base.h>
#include <stdlib.h>

/**
  If no heartbeat arrives in microseconds, the watchdog timeout event
  should terminate the session.

  @param[in] microseconds     heartbeat period, in microseconds.

**/
boolean init_watchdog(uint64_t microseconds)
{
    return TRUE;
}

/**
  Reset the watchdog in heartbeat response.

**/
boolean reset_watchdog()
{
    return TRUE;
}
