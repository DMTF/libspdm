/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_device_secret_lib_internal.h>
#include <spdm_responder_lib_internal.h>

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

spdm_test_context_t m_spdm_responder_finish_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

typedef struct {
	spdm_message_header_t header;
	uint8 signature[MAX_ASYM_KEY_SIZE];
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

spdm_finish_request_mine_t m_spdm_finish_request1 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request1_size = sizeof(m_spdm_finish_request1);

void test_spdm_responder_finish(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	void *data;
	uintn data_size;
	spdm_session_info_t *session_info;
	uint32 session_id;

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
	spdm_context->connection_info.algorithm.base_asym_algo =
		SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
	spdm_context->connection_info.algorithm.measurement_spec =
		SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
	spdm_context->connection_info.algorithm.dhe_named_group =
		SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->connection_info.local_used_cert_chain_buffer = data;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size;
	spdm_context->local_context.slot_count = 1;
	spdm_reset_message_a(spdm_context);
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

	response_size = sizeof(response);
	spdm_get_response_finish(spdm_context,
				 spdm_test_context->test_buffer_size,
				 spdm_test_context->test_buffer, &response_size,
				 response);
}

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(&m_spdm_responder_finish_test_context);

	m_spdm_responder_finish_test_context.test_buffer = test_buffer;
	m_spdm_responder_finish_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_responder_finish(&State);

	spdm_unit_test_group_teardown(&State);
}
