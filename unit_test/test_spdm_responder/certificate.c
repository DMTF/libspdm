/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

#if SPDM_ENABLE_CAPABILITY_CERT_CAP

// #define TEST_DEBUG
#ifdef TEST_DEBUG
#define TEST_DEBUG_PRINT(format, ...) printf(format, ##__VA_ARGS__)
#else
#define TEST_DEBUG_PRINT(...)
#endif

spdm_get_certificate_request_t m_spdm_get_certificate_request1 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_CERTIFICATE, 0, 0 },
	0,
	MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
uintn m_spdm_get_certificate_request1_size =
	sizeof(m_spdm_get_certificate_request1);

spdm_get_certificate_request_t m_spdm_get_certificate_request2 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_CERTIFICATE, 0, 0 },
	0,
	MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
uintn m_spdm_get_certificate_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

spdm_get_certificate_request_t m_spdm_get_certificate_request3 = {
	{ SPDM_MESSAGE_VERSION_10, SPDM_GET_CERTIFICATE, 0, 0 },
	0,
	0
};
uintn m_spdm_get_certificate_request3_size =
	sizeof(m_spdm_get_certificate_request3);

/**
  Test 1: request the first MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of the certificate chain
  Expected Behavior: generate a correctly formed Certficate message, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	spdm_context->transcript.message_m.buffer_size =
		spdm_context->transcript.message_m.max_buffer_size;
#endif

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request1_size,
		&m_spdm_get_certificate_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_certificate_response_t) +
						MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CERTIFICATE);
	assert_int_equal(spdm_response->header.param1, 0);
	assert_int_equal(spdm_response->portion_length,
			 MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
	assert_int_equal(spdm_response->remainder_length,
			 data_size - MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
	free(data);
}

/**
  Test 2: Wrong GET_CERTIFICATE message size (larger than expected)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
**/
void test_spdm_responder_certificate_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request2_size,
		&m_spdm_get_certificate_request2, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	free(data);
}

/**
  Test 3: Force response_state = SPDM_RESPONSE_STATE_BUSY when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
**/
void test_spdm_responder_certificate_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request1_size,
		&m_spdm_get_certificate_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
	free(data);
}

/**
  Test 4: Force response_state = SPDM_RESPONSE_STATE_NEED_RESYNC when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
**/
void test_spdm_responder_certificate_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request1_size,
		&m_spdm_get_certificate_request1, &response_size, response);
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
	free(data);
}

/**
  Test 5: Force response_state = SPDM_RESPONSE_STATE_NOT_READY when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_RESPONSE_NOT_READY and correct error_data
**/
void test_spdm_responder_certificate_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request1_size,
		&m_spdm_get_certificate_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	error_data = (spdm_error_data_response_not_ready_t
			      *)(&spdm_response->portion_length);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_GET_CERTIFICATE);
	free(data);
}

/**
  Test 6: simulate wrong connection_state when asked GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNEXPECTED_REQUEST
**/
void test_spdm_responder_certificate_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	response_size = sizeof(response);
	status = spdm_get_response_certificate(
		spdm_context, m_spdm_get_certificate_request1_size,
		&m_spdm_get_certificate_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
	free(data);
}

/**
  Test 7: request length at the boundary of maximum integer values, while keeping offset 0
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

	// Testing Lengths at the boundary of maximum integer values
	uint16 test_lenghts[] = {
		0,	    MAX_INT8,	 (uint16)(MAX_INT8 + 1),
		MAX_UINT8,  MAX_INT16,	 (uint16)(MAX_INT16 + 1),
		MAX_UINT16, (uint16)(-1)
	};
	uint16 expected_chunk_size;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// This tests considers only offset = 0, other tests vary offset value
	m_spdm_get_certificate_request3.offset = 0;

	for (int i = 0; i < sizeof(test_lenghts) / sizeof(test_lenghts[0]);
	     i++) {
		TEST_DEBUG_PRINT("i:%d test_lenghts[i]:%u\n", i,
				 test_lenghts[i]);
		m_spdm_get_certificate_request3.length = test_lenghts[i];
		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN (implementation specific?)
		expected_chunk_size =
			MIN(m_spdm_get_certificate_request3.length,
			    MAX_SPDM_CERT_CHAIN_BLOCK_LEN);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		spdm_reset_message_b(spdm_context);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		assert_int_equal(response_size,
				 sizeof(spdm_certificate_response_t) +
					 expected_chunk_size);
		spdm_response = (void *)response;
		assert_int_equal(spdm_response->header.request_response_code,
				 SPDM_CERTIFICATE);
		assert_int_equal(spdm_response->header.param1, 0);
		assert_int_equal(spdm_response->portion_length,
				 expected_chunk_size);
		assert_int_equal(spdm_response->remainder_length,
				 data_size - expected_chunk_size);
	}
	free(data);
}

/**
  Test 8: request offset at the boundary of maximum integer values, while keeping length 0
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	spdm_error_response_t *spdm_responseError;
	void *data;
	uintn data_size;

	// Testing offsets at the boundary of maximum integer values and at the boundary of certificate length (first three positions)
	uint16 test_offsets[] = { (uint16)(-1),
				  0,
				  +1,
				  0,
				  MAX_INT8,
				  (uint16)(MAX_INT8 + 1),
				  MAX_UINT8,
				  MAX_INT16,
				  (uint16)(MAX_INT16 + 1),
				  MAX_UINT16,
				  (uint16)(-1) };

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// This tests considers only length = 0, other tests vary length value
	m_spdm_get_certificate_request3.length = 0;
	// Setting up offset values at the boundary of certificate length
	test_offsets[0] = (uint16)(test_offsets[0] + data_size);
	test_offsets[1] = (uint16)(test_offsets[1] + data_size);
	test_offsets[2] = (uint16)(test_offsets[2] + data_size);

	for (int i = 0; i < sizeof(test_offsets) / sizeof(test_offsets[0]);
	     i++) {
		TEST_DEBUG_PRINT("i:%d test_offsets[i]:%u\n", i,
				 test_offsets[i]);
		m_spdm_get_certificate_request3.offset = test_offsets[i];

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		spdm_reset_message_b(spdm_context);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		if (m_spdm_get_certificate_request3.offset >= data_size) {
			// A too long of an offset should return an error
			spdm_responseError = (void *)response;
			assert_int_equal(
				spdm_responseError->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(spdm_responseError->header.param1,
					 SPDM_ERROR_CODE_INVALID_REQUEST);
		} else {
			// Otherwise it should work properly, considering length = 0
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t));
			spdm_response = (void *)response;
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length, 0);
			assert_int_equal(
				spdm_response->remainder_length,
				(uint16)(data_size -
					 m_spdm_get_certificate_request3
						 .offset));
		}
	}
	free(data);
}

/**
  Test 9: request offset and length at the boundary of maximum integer values
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	spdm_error_response_t *spdm_responseError;
	void *data;
	uintn data_size;

	// Testing offsets and length combinations
	// Check at the boundary of maximum integer values and at the boundary of certificate length
	uint16 test_sizes[] = {
		(uint16)(-1),
		0,
		+1, // reserved for sizes around the certificate chain size
		(uint16)(-1),
		0,
		+1,
		(uint16)(MAX_INT8 - 1),
		MAX_INT8,
		(uint16)(MAX_INT8 + 1),
		(uint16)(MAX_UINT8 - 1),
		MAX_UINT8,
		(uint16)(MAX_INT16 - 1),
		MAX_INT16,
		(uint16)(MAX_INT16 + 1),
		(uint16)(MAX_UINT16 - 1),
		MAX_UINT16
	};
	uint16 expected_chunk_size;
	uint16 expected_remainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// Setting up offset values at the boundary of certificate length
	test_sizes[0] += (uint16)(test_sizes[0] + data_size);
	test_sizes[1] += (uint16)(test_sizes[1] + data_size);
	test_sizes[2] += (uint16)(test_sizes[2] + data_size);

	for (int i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
		TEST_DEBUG_PRINT("i:%d test_sizes[i]=length:%u\n", i,
				 test_sizes[i]);
		m_spdm_get_certificate_request3.length = test_sizes[i];
		for (int j = 0; j < sizeof(test_sizes) / sizeof(test_sizes[0]);
		     j++) {
			TEST_DEBUG_PRINT("\tj:%d test_sizes[j]=offset:%u\n", j,
					 test_sizes[j]);
			m_spdm_get_certificate_request3.offset = test_sizes[j];

			// reseting an internal buffer to avoid overflow and prevent tests to succeed
			spdm_reset_message_b(spdm_context);
			response_size = sizeof(response);
			status = spdm_get_response_certificate(
				spdm_context,
				m_spdm_get_certificate_request3_size,
				&m_spdm_get_certificate_request3,
				&response_size, response);
			assert_int_equal(status, RETURN_SUCCESS);

			if (m_spdm_get_certificate_request3.offset >=
			    data_size) {
				// A too long of an offset should return an error
				spdm_responseError = (void *)response;
				assert_int_equal(spdm_responseError->header
							 .request_response_code,
						 SPDM_ERROR);
				assert_int_equal(
					spdm_responseError->header.param1,
					SPDM_ERROR_CODE_INVALID_REQUEST);
			} else {
				// Otherwise it should work properly

				// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
				expected_chunk_size = (uint16)(MIN(
					m_spdm_get_certificate_request3.length,
					data_size -
						m_spdm_get_certificate_request3
							.offset));
				expected_chunk_size =
					MIN(expected_chunk_size,
					    MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
				// Expected certificate length left
				expected_remainder =
					(uint16)(data_size -
						 m_spdm_get_certificate_request3
							 .offset -
						 expected_chunk_size);

				assert_int_equal(
					response_size,
					sizeof(spdm_certificate_response_t) +
						expected_chunk_size);
				spdm_response = (void *)response;
				assert_int_equal(spdm_response->header
							 .request_response_code,
						 SPDM_CERTIFICATE);
				assert_int_equal(spdm_response->header.param1,
						 0);
				assert_int_equal(spdm_response->portion_length,
						 expected_chunk_size);
				assert_int_equal(
					spdm_response->remainder_length,
					expected_remainder);
			}
		}
	}
	free(data);
}

/**
  Test 10: request MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of long certificate chains, with the largest valid offset
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	spdm_error_response_t *spdm_responseError;
	void *data;
	uintn data_size;

	uint16 test_cases[] = { TEST_CERT_MAXINT16, TEST_CERT_MAXUINT16 };

	uintn expected_chunk_size;
	uintn expected_remainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	m_spdm_get_certificate_request3.length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
		read_responder_public_certificate_chain_by_size(
			m_use_hash_algo, m_use_asym_algo, test_cases[i], &data,
			&data_size, NULL, NULL);

		spdm_context->local_context.local_cert_chain_provision[0] =
			data;
		spdm_context->local_context.local_cert_chain_provision_size[0] =
			data_size;
		spdm_context->local_context.slot_count = 1;

		m_spdm_get_certificate_request3.offset =
			(uint16)(MIN(data_size - 1, MAX_UINT16));
		TEST_DEBUG_PRINT("data_size: %u\n", data_size);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.offset: %u\n",
				 m_spdm_get_certificate_request3.offset);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.length: %u\n",
				 m_spdm_get_certificate_request3.length);
		TEST_DEBUG_PRINT(
			"offset + length: %u\n",
			m_spdm_get_certificate_request3.offset +
				m_spdm_get_certificate_request3.length);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		spdm_reset_message_b(spdm_context);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
		expected_chunk_size = (uint16)(MIN(
			m_spdm_get_certificate_request3.length,
			data_size - m_spdm_get_certificate_request3.offset));
		expected_chunk_size =
			MIN(expected_chunk_size, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
		// Expected certificate length left
		expected_remainder =
			(uint16)(data_size -
				 m_spdm_get_certificate_request3.offset -
				 expected_chunk_size);

		TEST_DEBUG_PRINT("expected_chunk_size %u\n",
				 expected_chunk_size);
		TEST_DEBUG_PRINT("expected_remainder %u\n", expected_remainder);

		if (expected_remainder > MAX_UINT16 ||
		    expected_chunk_size > MAX_UINT16) {
			spdm_responseError = (void *)response;
			assert_int_equal(
				spdm_responseError->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(spdm_responseError->header.param1,
					 SPDM_ERROR_CODE_INVALID_REQUEST);
		} else {
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t) +
						 expected_chunk_size);
			spdm_response = (void *)response;
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 expected_chunk_size);
			assert_int_equal(spdm_response->remainder_length,
					 expected_remainder);
		}

		TEST_DEBUG_PRINT("\n");

		spdm_context->local_context.local_cert_chain_provision[0] =
			NULL;
		spdm_context->local_context.local_cert_chain_provision_size[0] =
			0;
		free(data);
	}
}

/**
  Test 11: request MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of a short certificate chain (fits in 1 message)
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	spdm_error_response_t *spdm_responseError;
	void *data;
	uintn data_size;

	uint16 test_cases[] = { TEST_CERT_SMALL };

	uintn expected_chunk_size;
	uintn expected_remainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;

	m_spdm_get_certificate_request3.length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	m_spdm_get_certificate_request3.offset = 0;

	for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
		read_responder_public_certificate_chain_by_size(
			m_use_hash_algo, m_use_asym_algo, test_cases[i], &data,
			&data_size, NULL, NULL);
		spdm_context->local_context.local_cert_chain_provision[0] =
			data;
		spdm_context->local_context.local_cert_chain_provision_size[0] =
			data_size;
		spdm_context->local_context.slot_count = 1;

		TEST_DEBUG_PRINT("data_size: %u\n", data_size);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.offset: %u\n",
				 m_spdm_get_certificate_request3.offset);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.length: %u\n",
				 m_spdm_get_certificate_request3.length);
		TEST_DEBUG_PRINT(
			"offset + length: %u\n",
			m_spdm_get_certificate_request3.offset +
				m_spdm_get_certificate_request3.length);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		spdm_reset_message_b(spdm_context);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
		expected_chunk_size =
			MIN(m_spdm_get_certificate_request3.length,
			    data_size - m_spdm_get_certificate_request3.offset);
		expected_chunk_size =
			MIN(expected_chunk_size, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
		// Expected certificate length left
		expected_remainder = data_size -
				     m_spdm_get_certificate_request3.offset -
				     expected_chunk_size;

		TEST_DEBUG_PRINT("expected_chunk_size %u\n",
				 expected_chunk_size);
		TEST_DEBUG_PRINT("expected_remainder %u\n", expected_remainder);

		if (expected_remainder > MAX_UINT16 ||
		    expected_chunk_size > MAX_UINT16) {
			spdm_responseError = (void *)response;
			assert_int_equal(
				spdm_responseError->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(spdm_responseError->header.param1,
					 SPDM_ERROR_CODE_INVALID_REQUEST);
		} else {
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t) +
						 expected_chunk_size);
			spdm_response = (void *)response;
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 expected_chunk_size);
			assert_int_equal(spdm_response->remainder_length,
					 expected_remainder);
		}

		TEST_DEBUG_PRINT("\n");

		free(data);
	}
}

/**
  Test 12: request a whole certificate chain byte by byte
  Expected Behavior: generate correctly formed Certficate messages, including its portion_length and remainder_length fields
**/
void test_spdm_responder_certificate_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_certificate_response_t *spdm_response;
	void *data;
	uintn data_size;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	uintn count;
#endif
	uint16 expected_chunk_size;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// This tests considers only length = 1
	m_spdm_get_certificate_request3.length = 1;
	expected_chunk_size = 1;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
	count = (data_size + m_spdm_get_certificate_request3.length - 1) /
		m_spdm_get_certificate_request3.length;
#endif

	// reseting an internal buffer to avoid overflow and prevent tests to succeed
	spdm_reset_message_b(spdm_context);

	spdm_response = NULL;
	for (uintn offset = 0; offset < data_size; offset++) {
		TEST_DEBUG_PRINT("offset:%u \n", offset);
		m_spdm_get_certificate_request3.offset = (uint16)offset;

		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		spdm_response = (void *)response;
		// It may fail because the spdm does not support too many messages.
		// assert_int_equal (spdm_response->header.request_response_code, SPDM_CERTIFICATE);
		if (spdm_response->header.request_response_code ==
		    SPDM_CERTIFICATE) {
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t) +
						 expected_chunk_size);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 expected_chunk_size);
			assert_int_equal(spdm_response->remainder_length,
					 data_size - offset -
						 expected_chunk_size);
			assert_int_equal(
				((uint8 *)data)[offset],
				(response +
				 sizeof(spdm_certificate_response_t))[0]);
		} else {
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_ERROR);
			break;
		}
	}
	if (spdm_response != NULL) {
		if (spdm_response->header.request_response_code ==
		    SPDM_CERTIFICATE) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
			assert_int_equal(
				spdm_context->transcript.message_b.buffer_size,
				sizeof(spdm_get_certificate_request_t) * count +
					sizeof(spdm_certificate_response_t) *
						count +
					data_size);
#endif
		}
	}
	free(data);
}

spdm_test_context_t m_spdm_responder_certificate_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_certificate_test_main(void)
{
	const struct CMUnitTest spdm_responder_certificate_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_certificate_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_certificate_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_certificate_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_certificate_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_certificate_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_certificate_case6),
		// Tests varying length
		cmocka_unit_test(test_spdm_responder_certificate_case7),
		// Tests varying offset
		cmocka_unit_test(test_spdm_responder_certificate_case8),
		// Tests varying length and offset
		cmocka_unit_test(test_spdm_responder_certificate_case9),
		// Tests large certificate chains
		cmocka_unit_test(test_spdm_responder_certificate_case10),
		// Certificate fits in one single message
		cmocka_unit_test(test_spdm_responder_certificate_case11),
		// Requests byte by byte
		cmocka_unit_test(test_spdm_responder_certificate_case12),

	};

	setup_spdm_test_context(&m_spdm_responder_certificate_test_context);

	return cmocka_run_group_tests(spdm_responder_certificate_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}

#endif // SPDM_ENABLE_CAPABILITY_CERT_CAP
