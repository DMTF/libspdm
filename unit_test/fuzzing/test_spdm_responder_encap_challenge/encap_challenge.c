/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_device_secret_lib_internal.h>
#include <internal/libspdm_responder_lib.h>


uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_encap_challenge_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

void test_spdm_responder_encap_challenge(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	void *data;
	uintn data_size;
	boolean *need_continue;

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;

	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	libspdm_reset_message_c(spdm_context);

	*need_continue = FALSE;
	spdm_process_encap_response_challenge_auth(
		spdm_context, spdm_test_context->test_buffer_size,
		spdm_test_context->test_buffer, need_continue);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_responder_encap_challenge_test_context);

	m_spdm_responder_encap_challenge_test_context.test_buffer = test_buffer;
	m_spdm_responder_encap_challenge_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_encap_challenge(&State);

	spdm_unit_test_group_teardown(&State);
}
