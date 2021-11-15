/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_device_secret_lib_internal.h>
#include <spdm_responder_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

#define MY_TEST_TOKEN 0x30

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_if_ready_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

spdm_response_if_ready_request_t m_spdm_respond_if_ready_request = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_RESPOND_IF_READY, SPDM_GET_DIGESTS,
	  MY_TEST_TOKEN },
};

void test_spdm_responder_respond_if_ready(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	static uint8 m_local_certificate_chain[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	uintn m_spdm_respond_if_ready_request_size =
		sizeof(spdm_message_header_t);
	spdm_get_digest_request_t m_spdm_get_digest_request = {
		{ SPDM_MESSAGE_VERSION_11, SPDM_GET_DIGESTS, 0, 0 },
	};

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	uintn m_spdm_get_digest_request_size = sizeof(spdm_message_header_t);

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->local_context.local_cert_chain_provision[0] =
		m_local_certificate_chain;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		MAX_SPDM_MESSAGE_BUFFER_SIZE;
	set_mem(m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE,
		(uint8)(0xFF));
	spdm_context->local_context.slot_count = 1;

	spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
	copy_mem(spdm_context->last_spdm_request, &m_spdm_get_digest_request,
		 m_spdm_get_digest_request_size);

	//RESPOND_IF_READY specific data
	spdm_context->cache_spdm_request_size =
		spdm_context->last_spdm_request_size;
	copy_mem(spdm_context->cache_spdm_request,
		 spdm_context->last_spdm_request,
		 spdm_context->last_spdm_request_size);
	spdm_context->error_data.rd_exponent = 1;
	spdm_context->error_data.rd_tm = 1;
	spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
	spdm_context->error_data.token = MY_TEST_TOKEN;

	//check DIGESTS response
	response_size = sizeof(response);
	spdm_get_response_respond_if_ready(spdm_context,
					   m_spdm_respond_if_ready_request_size,
					   &m_spdm_respond_if_ready_request,
					   &response_size, response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_responder_if_ready_test_context);

	m_spdm_responder_if_ready_test_context.test_buffer = test_buffer;
	m_spdm_responder_if_ready_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_respond_if_ready(&State);

	spdm_unit_test_group_teardown(&State);
}
