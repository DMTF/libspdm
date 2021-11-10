/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_requester_lib_internal.h>

uint8 m_use_measurement_spec = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
uint32 m_use_measurement_hash_algo =
	SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
uint32 m_use_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
uint32 m_use_asym_algo =
	SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
uint16 m_use_req_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
uint16 m_use_dhe_algo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
uint16 m_use_aead_algo = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
uint16 m_use_key_schedule_algo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

uintn get_max_buffer_size(void)
{
	return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

return_status spdm_device_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64 timeout)
{
	return RETURN_SUCCESS;
}

return_status spdm_device_receive_message(IN void *spdm_context,
					  IN OUT uintn *response_size,
					  IN OUT void *response,
					  IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	*response_size = spdm_test_context->test_buffer_size;
	copy_mem(response, spdm_test_context->test_buffer,
		 spdm_test_context->test_buffer_size);

	return RETURN_SUCCESS;
}


void test_spdm_requester_get_measurement(void **State)
{
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uint8 number_of_block;
	uint32 measurement_record_length;
	uint8 measurement_record[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
	uint8 request_attribute;
	void *data;
	uintn data_size;

	spdm_test_context = *State;
	spdm_context = spdm_test_context->spdm_context;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.peer_used_cert_chain_buffer_size =
		data_size;
	copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
		 data, data_size);
	request_attribute =
		SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

	measurement_record_length = sizeof(measurement_record);
	spdm_get_measurement(spdm_context, NULL, request_attribute, 1, 0,
			     &number_of_block, &measurement_record_length,
			     measurement_record);
}

spdm_test_context_t m_spdm_requester_get_measurements_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_device_send_message,
	spdm_device_receive_message,
};

// spdm_test_context_t m_spdm_requester_get_measurements_test_context = {
// 	SPDM_TEST_CONTEXT_SIGNATURE,
// 	TRUE,
// 	spdm_requester_get_measurements_test_send_message,
// 	spdm_requester_get_measurements_test_receive_message,
// };

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
	void *State;

	setup_spdm_test_context(
		&m_spdm_requester_get_measurements_test_context);

	m_spdm_requester_get_measurements_test_context.test_buffer =
		test_buffer;
	m_spdm_requester_get_measurements_test_context.test_buffer_size =
		test_buffer_size;

	spdm_unit_test_group_setup(&State);

	test_spdm_requester_get_measurement(&State);

	spdm_unit_test_group_teardown(&State);
}
