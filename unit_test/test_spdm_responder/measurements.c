/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

spdm_get_measurements_request_t m_spdm_get_measurements_request1 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0,
	  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
uintn m_spdm_get_measurements_request1_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_spdm_get_measurements_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0,
	  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
uintn m_spdm_get_measurements_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

spdm_get_measurements_request_t m_spdm_get_measurements_request3 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
uintn m_spdm_get_measurements_request3_size =
	sizeof(m_spdm_get_measurements_request3) - sizeof(uint8);

spdm_get_measurements_request_t m_spdm_get_measurements_request4 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
uintn m_spdm_get_measurements_request4_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_spdm_get_measurements_request5 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
	  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
uintn m_spdm_get_measurements_request5_size =
	sizeof(m_spdm_get_measurements_request5) - sizeof(uint8);

spdm_get_measurements_request_t m_spdm_get_measurements_request6 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0, 1 },
};
uintn m_spdm_get_measurements_request6_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_spdm_get_measurements_request7 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0,
	  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS },
};
uintn m_spdm_get_measurements_request7_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_spdm_get_measurements_request8 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
	  SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS },
};
uintn m_spdm_get_measurements_request8_size =
	sizeof(m_spdm_get_measurements_request8) - sizeof(uint8);

spdm_get_measurements_request_t m_spdm_get_measurements_request9 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS, 0, 1 },
};
uintn m_spdm_get_measurements_request9_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_spdm_get_measurements_request10 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
uintn m_spdm_get_measurements_request10_size =
	sizeof(m_spdm_get_measurements_request10);

spdm_get_measurements_request_t m_spdm_get_measurements_request11 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
	// nonce
	// SlotId != 0
};
uintn m_spdm_get_measurements_request11_size =
	sizeof(m_spdm_get_measurements_request11);

spdm_get_measurements_request_t m_spdm_get_measurements_request12 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
	  SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
	// nonce
	// SlotId >= MAX_SPDM_SLOT_COUNT
};
uintn m_spdm_get_measurements_request12_size =
	sizeof(m_spdm_get_measurements_request12);

spdm_get_measurements_request_t m_spdm_get_measurements_request13 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS, 0, 0xFE },
};
uintn m_spdm_get_measurements_request13_size = sizeof(spdm_message_header_t);

/**
  Test 1: Successful response to get a number of measurements without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
**/
void test_spdm_responder_measurements_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request1.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request1_size,
		&m_spdm_get_measurements_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) + SPDM_NONCE_SIZE + sizeof(uint16));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_response->header.param1,
			 MEASUREMENT_BLOCK_NUMBER);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size,
			 m_spdm_get_measurements_request1_size +
				 sizeof(spdm_measurements_response_t) +
				 SPDM_NONCE_SIZE +
				 sizeof(uint16));
}

/**
  Test 2: Error case, Bad request size (MAX_SPDM_MESSAGE_BUFFER_SIZE) to get measurement number without signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request2.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request2_size,
		&m_spdm_get_measurements_request2, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 3: Force response_state = SPDM_RESPONSE_STATE_BUSY when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
**/
void test_spdm_responder_measurements_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request1.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request1_size,
		&m_spdm_get_measurements_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 4: Force response_state = SPDM_RESPONSE_STATE_NEED_RESYNC when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
**/
void test_spdm_responder_measurements_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request1.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request1_size,
		&m_spdm_get_measurements_request1, &response_size, response);
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
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 5: Force response_state = SPDM_RESPONSE_STATE_NOT_READY when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
**/
void test_spdm_responder_measurements_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request1.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request1_size,
		&m_spdm_get_measurements_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	error_data = (spdm_error_data_response_not_ready_t
			      *)(&spdm_response->number_of_blocks);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_GET_MEASUREMENTS);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 6: simulate wrong connection_state when asked GET_MEASUREMENTS
          (missing SPDM_GET_DIGESTS_RECEIVE_FLAG, SPDM_GET_CAPABILITIES_RECEIVE_FLAG and SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNEXPECTED_REQUEST
**/
void test_spdm_responder_measurements_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request1.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request1_size,
		&m_spdm_get_measurements_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 7: Successful response to get a number of measurements with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
**/
void test_spdm_responder_measurements_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uintn measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 +
			      spdm_get_asym_signature_size(m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request5.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request5_size,
		&m_spdm_get_measurements_request5, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
						measurment_sig_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_response->header.param1,
			 MEASUREMENT_BLOCK_NUMBER);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 8: Successful response to get one measurement with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
**/
void test_spdm_responder_measurements_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uintn measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 +
			      spdm_get_asym_signature_size(m_use_asym_algo);
	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request3.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request3_size,
		&m_spdm_get_measurements_request3, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) +
				 sizeof(spdm_measurement_block_dmtf_t) +
				 spdm_get_measurement_hash_size(
					 m_use_measurement_hash_algo) +
				 measurment_sig_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 9: Error case, Bad request size (sizeof(spdm_message_header_t)x) to get measurement number with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request4.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request4_size,
		&m_spdm_get_measurements_request4, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 10: Successful response to get one measurement without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
**/
void test_spdm_responder_measurements_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request6.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request6_size,
		&m_spdm_get_measurements_request6, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) +
				 sizeof(spdm_measurement_block_dmtf_t) +
				 spdm_get_measurement_hash_size(
					 m_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
				 sizeof(uint16));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size,
			 m_spdm_get_measurements_request6_size +
				 sizeof(spdm_measurements_response_t) +
				 sizeof(spdm_measurement_block_dmtf_t) +
				 spdm_get_measurement_hash_size(
					 m_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
				 sizeof(uint16));
}

/**
  Test 11: Successful response to get all measurements with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
**/
void test_spdm_responder_measurements_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uintn measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 +
			      spdm_get_asym_signature_size(m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request8.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request8_size,
		&m_spdm_get_measurements_request8, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) +
				 (MEASUREMENT_BLOCK_NUMBER -
				  1) * (sizeof(spdm_measurement_block_dmtf_t) +
					spdm_get_measurement_hash_size(
						m_use_measurement_hash_algo)) +
				 (sizeof(spdm_measurement_block_dmtf_t) +
				  MEASUREMENT_MANIFEST_SIZE) +
				 measurment_sig_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_response->number_of_blocks,
			 MEASUREMENT_BLOCK_NUMBER);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 12: Successful response to get all measurements without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
**/
void test_spdm_responder_measurements_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request7.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request7_size,
		&m_spdm_get_measurements_request7, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) +
				 (MEASUREMENT_BLOCK_NUMBER -
				  1) * (sizeof(spdm_measurement_block_dmtf_t) +
					spdm_get_measurement_hash_size(
						m_use_measurement_hash_algo)) +
				 (sizeof(spdm_measurement_block_dmtf_t) +
				  MEASUREMENT_MANIFEST_SIZE) + SPDM_NONCE_SIZE +
				 sizeof(uint16));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_response->number_of_blocks,
			 MEASUREMENT_BLOCK_NUMBER);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size,
			 m_spdm_get_measurements_request7_size +
				 sizeof(spdm_measurements_response_t) +
				 (MEASUREMENT_BLOCK_NUMBER -
				  1) * (sizeof(spdm_measurement_block_dmtf_t) +
					spdm_get_measurement_hash_size(
						m_use_measurement_hash_algo)) +
				 (sizeof(spdm_measurement_block_dmtf_t) +
				  MEASUREMENT_MANIFEST_SIZE) + SPDM_NONCE_SIZE +
				 sizeof(uint16));
}

/**
  Test 13: Error case, even though signature was not required, there is nonce and/or slotID
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case13(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uint16 TestMsgSizes[3];

	TestMsgSizes[0] =
		(uint16)(m_spdm_get_measurements_request9_size +
			 sizeof(m_spdm_get_measurements_request9.SlotIDParam) +
			 sizeof(m_spdm_get_measurements_request9.nonce));
	TestMsgSizes[1] =
		(uint16)(m_spdm_get_measurements_request9_size +
			 sizeof(m_spdm_get_measurements_request9.SlotIDParam));
	TestMsgSizes[2] =
		(uint16)(m_spdm_get_measurements_request9_size +
			 sizeof(m_spdm_get_measurements_request9.nonce));

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xD;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request9.nonce);
	for (int i = 0; i < sizeof(TestMsgSizes) / sizeof(TestMsgSizes[0]);
	     i++) {
		response_size = sizeof(response);
		status = spdm_get_response_measurements(
			spdm_context, TestMsgSizes[i],
			&m_spdm_get_measurements_request9, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		assert_int_equal(response_size, sizeof(spdm_error_response_t));
		spdm_response = (void *)response;
		assert_int_equal(spdm_response->header.request_response_code,
				 SPDM_ERROR);
		assert_int_equal(spdm_response->header.param1,
				 SPDM_ERROR_CODE_INVALID_REQUEST);
		assert_int_equal(spdm_response->header.param2, 0);
		assert_int_equal(spdm_context->transcript.message_m.buffer_size,
				 0);
	}
}

/**
  Test 14: Error case, signature was required, but there is no nonce and/or slotID
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case14(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uint16 TestMsgSizes[3];

	TestMsgSizes[0] =
		(uint16)(m_spdm_get_measurements_request10_size -
			 sizeof(m_spdm_get_measurements_request10.SlotIDParam) -
			 sizeof(m_spdm_get_measurements_request10.nonce));
	TestMsgSizes[1] =
		(uint16)(m_spdm_get_measurements_request10_size -
			 sizeof(m_spdm_get_measurements_request10.SlotIDParam));
	TestMsgSizes[2] =
		(uint16)(m_spdm_get_measurements_request10_size -
			 sizeof(m_spdm_get_measurements_request10.nonce));

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xE;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request10.nonce);
	for (int i = 0; i < sizeof(TestMsgSizes) / sizeof(TestMsgSizes[0]);
	     i++) {
		response_size = sizeof(response);
		status = spdm_get_response_measurements(
			spdm_context, TestMsgSizes[i],
			&m_spdm_get_measurements_request10, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		assert_int_equal(response_size, sizeof(spdm_error_response_t));
		spdm_response = (void *)response;
		assert_int_equal(spdm_response->header.request_response_code,
				 SPDM_ERROR);
		assert_int_equal(spdm_response->header.param1,
				 SPDM_ERROR_CODE_INVALID_REQUEST);
		assert_int_equal(spdm_response->header.param2, 0);
		assert_int_equal(spdm_context->transcript.message_m.buffer_size,
				 0);
	}
}

/**
  Test 15: Error case, meas_cap = 01b, but signature was requested (request message includes nonce and slotID)
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case15(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	// uintn                measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xF;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	// measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request10.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request10_size,
		&m_spdm_get_measurements_request10, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 16: Error case, meas_cap = 01b, but signature was requested (request message does not include nonce and slotID)
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case16(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	// uintn                measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x10;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	// measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo);

	response_size = sizeof(response);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request9_size,
		&m_spdm_get_measurements_request10, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 17: Error case, meas_cap = 00
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case17(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	// uintn                measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x11;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags = 0;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	;
	// measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request9.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request9_size,
		&m_spdm_get_measurements_request9, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
	assert_int_equal(
		spdm_response->header.param2,
		m_spdm_get_measurements_request10.header.request_response_code);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 18: Successful response to get one measurement with signature, SlotId different from default
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
**/
void test_spdm_responder_measurements_case18(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	void *data;
	uintn data_size;
	uintn measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x12;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 +
			      spdm_get_asym_signature_size(m_use_asym_algo);
	spdm_context->local_context.slot_count = MAX_SPDM_SLOT_COUNT;
	for (int i = 1; i < spdm_context->local_context.slot_count; i++) {
		spdm_context->local_context.local_cert_chain_provision_size[i] =
			data_size;
		spdm_context->local_context.local_cert_chain_provision[i] =
			data;
	}

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request11.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request11_size,
		&m_spdm_get_measurements_request11, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_measurements_response_t) +
				 sizeof(spdm_measurement_block_dmtf_t) +
				 spdm_get_measurement_hash_size(
					 m_use_measurement_hash_algo) +
				 measurment_sig_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_MEASUREMENTS);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
	assert_int_equal(m_spdm_get_measurements_request11.SlotIDParam,
			 spdm_response->header.param2);

	spdm_context->local_context.slot_count = 1;
	free(data);
}

/**
  Test 19: Error case, invalid SlotId parameter (SlotId >= MAX_SPDM_SLOT_COUNT)
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case19(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	// uintn                measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x13;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	// measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request12.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request12_size,
		&m_spdm_get_measurements_request12, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 19: Error case, invalid SlotId parameter (slot_count < SlotId < MAX_SPDM_SLOT_COUNT)
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case20(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	// uintn                measurment_sig_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x14;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;
	// measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo);

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request11.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request11_size,
		&m_spdm_get_measurements_request11, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 21: Error case, request a measurement index larger than the total number of measurements
  Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
**/
void test_spdm_responder_measurements_case21(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x15;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	response_size = sizeof(response);
	spdm_get_random_number(SPDM_NONCE_SIZE,
			       m_spdm_get_measurements_request13.nonce);
	status = spdm_get_response_measurements(
		spdm_context, m_spdm_get_measurements_request13_size,
		&m_spdm_get_measurements_request13, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
}

/**
  Test 22: request a large number of measurements before requesting a singed response
  Expected Behavior: while transcript.message_m is not full, get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
                      if transcript.message_m has no more room, an error response is expected
**/
void test_spdm_responder_measurements_case22(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_measurements_response_t *spdm_response;
	uintn NumberOfMessages;
#define TOTAL_MESSAGES 100

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x16;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AUTHENTICATED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;
	spdm_context->transcript.message_m.buffer_size = 0;
	spdm_context->local_context.opaque_measurement_rsp_size = 0;
	spdm_context->local_context.opaque_measurement_rsp = NULL;

	for (NumberOfMessages = 1; NumberOfMessages <= TOTAL_MESSAGES;
	     NumberOfMessages++) {
		spdm_get_random_number(SPDM_NONCE_SIZE,
				       m_spdm_get_measurements_request6.nonce);
		response_size = sizeof(response);
		status = spdm_get_response_measurements(
			spdm_context, m_spdm_get_measurements_request6_size,
			&m_spdm_get_measurements_request6, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		spdm_response = (void *)response;
		if (spdm_response->header.request_response_code ==
		    SPDM_MEASUREMENTS) {
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_MEASUREMENTS);
			assert_int_equal(
				response_size,
				sizeof(spdm_measurements_response_t) +
					sizeof(spdm_measurement_block_dmtf_t) +
					spdm_get_measurement_hash_size(
						m_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
					sizeof(uint16));
			assert_int_equal(
				spdm_context->transcript.message_m.buffer_size,
				NumberOfMessages *
					(m_spdm_get_measurements_request6_size +
					 sizeof(spdm_measurements_response_t) +
					 sizeof(spdm_measurement_block_dmtf_t) +
					 spdm_get_measurement_hash_size(
						 m_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
					 sizeof(uint16)));
		} else {
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(
				spdm_context->transcript.message_m.buffer_size,
				0);
			break;
		}
	}
}

spdm_test_context_t m_spdm_responder_measurements_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_measurements_test_main(void)
{
	m_spdm_get_measurements_request11.SlotIDParam = MAX_SPDM_SLOT_COUNT - 1;
	m_spdm_get_measurements_request12.SlotIDParam = MAX_SPDM_SLOT_COUNT + 1;

	const struct CMUnitTest spdm_responder_measurements_tests[] = {
		// Success Case to get measurement number without signature
		cmocka_unit_test(test_spdm_responder_measurements_case1),
		// Bad request size to get measurement number without signature
		cmocka_unit_test(test_spdm_responder_measurements_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_measurements_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_measurements_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_measurements_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_measurements_case6),
		// Success Case to get measurement number with signature
		cmocka_unit_test(test_spdm_responder_measurements_case7),
		// Success Case to get one measurement with signature
		cmocka_unit_test(test_spdm_responder_measurements_case8),
		// Bad request size to get one measurement with signature
		cmocka_unit_test(test_spdm_responder_measurements_case9),
		// Success Case to get one measurement without signature
		cmocka_unit_test(test_spdm_responder_measurements_case10),
		// Success Case to get all measurements with signature
		cmocka_unit_test(test_spdm_responder_measurements_case11),
		// Success Case to get all measurements without signature
		cmocka_unit_test(test_spdm_responder_measurements_case12),
		// Error Case: no sig required, but there is nonce and/or slotID (special case of Test Case 2)
		cmocka_unit_test(test_spdm_responder_measurements_case13),
		// Error Case: sig required, but no nonce and/or SlotID
		cmocka_unit_test(test_spdm_responder_measurements_case14),
		// Error Case: sig required, but meas_cap = 01b (including nonce and SlotId on request)
		cmocka_unit_test(test_spdm_responder_measurements_case15),
		// Error Case: sig required, but meas_cap = 01b (not including nonce and SlotId on request)
		cmocka_unit_test(test_spdm_responder_measurements_case16),
		// Error Case: meas_cap = 00b
		cmocka_unit_test(test_spdm_responder_measurements_case17),
		// Success Case: SlotId different from default
		cmocka_unit_test(test_spdm_responder_measurements_case18),
		// Bad SlotId parameter (>= MAX_SPDM_SLOT_COUNT)
		cmocka_unit_test(test_spdm_responder_measurements_case19),
		// Bad SlotId parameter (slot_count < SlotId < MAX_SPDM_SLOT_COUNT)
		cmocka_unit_test(test_spdm_responder_measurements_case20),
		// Error Case: request a measurement out of bounds
		cmocka_unit_test(test_spdm_responder_measurements_case21),
		// Large number of requests before requiring a signature
		cmocka_unit_test(test_spdm_responder_measurements_case22),
	};

	setup_spdm_test_context(&m_spdm_responder_measurements_test_context);

	return cmocka_run_group_tests(spdm_responder_measurements_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
