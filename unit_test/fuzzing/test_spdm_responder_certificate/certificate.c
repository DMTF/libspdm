/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_responder_lib_internal.h>
#include <spdm_device_secret_lib_internal.h>


uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_certificate_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

spdm_get_certificate_request_t m_spdm_get_certificate_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_CERTIFICATE, 0, 0 },
	0,
	MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};

void test_spdm_responder_certificate(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	void *data;
	uintn data_size;


	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

	spdm_context->connection_info.algorithm.base_hash_algo =
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;

	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_response_certificate(spdm_context,
				      MAX_SPDM_MESSAGE_BUFFER_SIZE,
				      &m_spdm_get_certificate_request2,
				      &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_responder_certificate_test_context);

	m_spdm_responder_certificate_test_context.test_buffer = test_buffer;
	m_spdm_responder_certificate_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_certificate(&State);

	spdm_unit_test_group_teardown(&State);
}
