/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_UNIT_TEST_H__
#define __SPDM_UNIT_TEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

#undef NULL
#include <base.h>
#include <library/memlib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_transport_test_lib.h>
#include <spdm_common_lib_internal.h>

#define SPDM_TEST_CONTEXT_SIGNATURE SIGNATURE_32('S', 'T', 'C', 'S')

typedef struct {
	uint32 signature;
	boolean is_requester;
	spdm_device_send_message_func send_message;
	spdm_device_receive_message_func receive_message;
	void *spdm_context;
	void *test_buffer;
	uintn test_buffer_size;
} spdm_test_context_t;

#define SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(a)                                \
	BASE_CR(a, spdm_test_context_t, SpdmProtocol)
#define SPDM_TEST_CONTEXT_FROM_SPDM_CONTEXT(a)                                 \
	BASE_CR(a, spdm_test_context_t, spdm_context)

uintn spdm_unit_test_group_setup(void **State);

uintn spdm_unit_test_group_teardown(void **State);

void setup_spdm_test_context(IN spdm_test_context_t *spdm_test_context);

spdm_test_context_t *get_spdm_test_context(void);

#endif