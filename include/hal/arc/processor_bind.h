/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __PROCESSOR_BIND_H__
#define __PROCESSOR_BIND_H__


/* Define the processor type so other code can make processor based choices*/

#define MDE_CPU_ARC


/* Make sure we are using the correct packing rules per EFI specification*/

#if !defined(__GNUC__)
#pragma pack()
#endif

#ifndef LIBSPDM_STDINT_ALT
#include <stdint.h>
#else
#include LIBSPDM_STDINT_ALT
#endif


typedef unsigned char boolean;


/* Processor specific defines*/



/* A value of native width with the highest bit set.*/

#define MAX_BIT 0x80000000


/* Maximum legal arc address*/

#define MAX_ADDRESS 0xFFFFFFFF


/* Maximum legal arc intn values.*/

#define MAX_INTN ((intn)0x7FFFFFFF)

#endif
