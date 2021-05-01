/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

spdm_negotiate_algorithms_request_t m_spdm_negotiate_algorithms_request1 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
	sizeof(spdm_negotiate_algorithms_request_t),
	SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
uintn m_spdm_negotiate_algorithms_request1_size =
	sizeof(m_spdm_negotiate_algorithms_request1);

spdm_negotiate_algorithms_request_t m_spdm_negotiate_algorithms_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
	sizeof(spdm_negotiate_algorithms_request_t),
	SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
uintn m_spdm_negotiate_algorithms_request2_size = sizeof(spdm_message_header_t);

void test_spdm_responder_algorithms_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ALGORITHMS);
}

void test_spdm_responder_algorithms_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request2_size,
		&m_spdm_negotiate_algorithms_request2, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_algorithms_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
}

void test_spdm_responder_algorithms_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
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
}

void test_spdm_responder_algorithms_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	error_data =
		(spdm_error_data_response_not_ready_t *)(&spdm_response->length);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_NEGOTIATE_ALGORITHMS);
}

void test_spdm_responder_algorithms_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_algorithms_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;

	response_size = sizeof(response);
	status = spdm_get_response_algorithms(
		spdm_context, m_spdm_negotiate_algorithms_request1_size,
		&m_spdm_negotiate_algorithms_request1, &response_size,
		response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

spdm_test_context_t m_spdm_responder_algorithms_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_algorithms_test_main(void)
{
	const struct CMUnitTest spdm_responder_algorithms_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_algorithms_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_algorithms_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_algorithms_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_algorithms_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_algorithms_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_algorithms_case6),
	};

	m_spdm_negotiate_algorithms_request1.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithms_request1.bash_hash_algo = m_use_hash_algo;
	m_spdm_negotiate_algorithms_request2.base_asym_algo = m_use_asym_algo;
	m_spdm_negotiate_algorithms_request2.bash_hash_algo = m_use_hash_algo;

	setup_spdm_test_context(&m_spdm_responder_algorithms_test_context);

	return cmocka_run_group_tests(spdm_responder_algorithms_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
