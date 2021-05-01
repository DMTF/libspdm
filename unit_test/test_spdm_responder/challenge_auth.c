/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

spdm_challenge_request_t m_spdm_challenge_request1 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_CHALLENGE, 0,
	  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request1_size = sizeof(m_spdm_challenge_request1);

spdm_challenge_request_t m_spdm_challenge_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_CHALLENGE, 0,
	  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

void test_spdm_responder_challenge_auth_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request1.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request1_size,
		&m_spdm_challenge_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_challenge_auth_response_t) +
				 spdm_get_hash_size(m_use_hash_algo) +
				 SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 +
				 spdm_get_asym_signature_size(m_use_asym_algo));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CHALLENGE_AUTH);
	assert_int_equal(spdm_response->header.param1, 0);
	assert_int_equal(spdm_response->header.param2, 1 << 0);
	free(data1);
}

void test_spdm_responder_challenge_auth_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request2.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request2_size,
		&m_spdm_challenge_request2, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	free(data1);
}

void test_spdm_responder_challenge_auth_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request1.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request1_size,
		&m_spdm_challenge_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
	free(data1);
}

void test_spdm_responder_challenge_auth_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request1.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request1_size,
		&m_spdm_challenge_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_REQUEST_RESYNCH);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NEED_RESYNC);
	free(data1);
}

void test_spdm_responder_challenge_auth_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request1.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request1_size,
		&m_spdm_challenge_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	error_data =
		(spdm_error_data_response_not_ready_t *)(spdm_response + 1);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_CHALLENGE);
	free(data1);
}

void test_spdm_responder_challenge_auth_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_challenge_auth_response_t *spdm_response;
	void *data1;
	uintn data_size1;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->connection_info.algorithm.bash_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_challenge_request1.nonce);
	status = spdm_get_response_challenge_auth(
		spdm_context, m_spdm_challenge_request1_size,
		&m_spdm_challenge_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	free(data1);
}

spdm_test_context_t m_spdm_responder_challenge_auth_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_challenge_auth_test_main(void)
{
	const struct CMUnitTest spdm_responder_challenge_auth_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_challenge_auth_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_challenge_auth_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_challenge_auth_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_challenge_auth_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_challenge_auth_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_challenge_auth_case6),
	};

	setup_spdm_test_context(&m_spdm_responder_challenge_auth_test_context);

	return cmocka_run_group_tests(spdm_responder_challenge_auth_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
