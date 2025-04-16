/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <time.h>

unsigned int
sleep (
  unsigned int  seconds
  )
{
  return 0;
}

int
gettimeofday (
  struct timeval   *tv,
  struct timezone  *tz
  )
{
  tv->tv_sec  = (long)time (NULL);
  tv->tv_usec = 0;
  return 0;
}