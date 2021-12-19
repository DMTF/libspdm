/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef _TOOLCHAIN_HARNESS_LIB_
#define _TOOLCHAIN_HARNESS_LIB_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_ALIGNMENT 4
#define TEST_MESSAGE_TYPE_SPDM 0x01
#define NULL ((void *)0)

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size);

uintn get_max_buffer_size(void);

uint8_t judge_requster_name(IN char8 *file_name);

#endif