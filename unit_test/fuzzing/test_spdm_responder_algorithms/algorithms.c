/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <internal/libspdm_responder_lib.h>

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_algorithms(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	response_size = sizeof(response);

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;

	spdm_get_response_algorithms(spdm_context,
				       spdm_test_context->test_buffer_size,
				       spdm_test_context->test_buffer,
				       &response_size, response);
}

spdm_test_context_t test_spdm_responder_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;
	setup_spdm_test_context(&test_spdm_responder_context);

	test_spdm_responder_context.test_buffer = test_buffer;
	test_spdm_responder_context.test_buffer_size = test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_algorithms(&State);

	spdm_unit_test_group_teardown(&State);
}
