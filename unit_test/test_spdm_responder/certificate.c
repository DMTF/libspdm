/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

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
	uint16 TestLenghts[] = {
		0,	    MAX_INT8,	 (uint16)(MAX_INT8 + 1),
		MAX_UINT8,  MAX_INT16,	 (uint16)(MAX_INT16 + 1),
		MAX_UINT16, (uint16)(-1)
	};
	uint16 ExpectedChunkSize;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// This tests considers only offset = 0, other tests vary offset value
	m_spdm_get_certificate_request3.Offset = 0;

	for (int i = 0; i < sizeof(TestLenghts) / sizeof(TestLenghts[0]); i++) {
		TEST_DEBUG_PRINT("i:%d TestLenghts[i]:%u\n", i, TestLenghts[i]);
		m_spdm_get_certificate_request3.length = TestLenghts[i];
		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN (implementation specific?)
		ExpectedChunkSize = MIN(m_spdm_get_certificate_request3.length,
					MAX_SPDM_CERT_CHAIN_BLOCK_LEN);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		reset_managed_buffer(&spdm_context->transcript.message_b);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);
		assert_int_equal(response_size,
				 sizeof(spdm_certificate_response_t) +
					 ExpectedChunkSize);
		spdm_response = (void *)response;
		assert_int_equal(spdm_response->header.request_response_code,
				 SPDM_CERTIFICATE);
		assert_int_equal(spdm_response->header.param1, 0);
		assert_int_equal(spdm_response->portion_length,
				 ExpectedChunkSize);
		assert_int_equal(spdm_response->remainder_length,
				 data_size - ExpectedChunkSize);
	}
	free(data);
}

/**
  Test 8: request Offset at the boundary of maximum integer values, while keeping length 0
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

	// Testing Offsets at the boundary of maximum integer values and at the boundary of certificate length (first three positions)
	uint16 TestOffsets[] = { (uint16)(-1),
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
	TestOffsets[0] = (uint16)(TestOffsets[0] + data_size);
	TestOffsets[1] = (uint16)(TestOffsets[1] + data_size);
	TestOffsets[2] = (uint16)(TestOffsets[2] + data_size);

	for (int i = 0; i < sizeof(TestOffsets) / sizeof(TestOffsets[0]); i++) {
		TEST_DEBUG_PRINT("i:%d TestOffsets[i]:%u\n", i, TestOffsets[i]);
		m_spdm_get_certificate_request3.Offset = TestOffsets[i];

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		reset_managed_buffer(&spdm_context->transcript.message_b);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		if (m_spdm_get_certificate_request3.Offset >= data_size) {
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
				(uint16)(
					data_size -
					m_spdm_get_certificate_request3.Offset));
		}
	}
	free(data);
}

/**
  Test 9: request Offset and length at the boundary of maximum integer values
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

	// Testing Offsets and length combinations
	// Check at the boundary of maximum integer values and at the boundary of certificate length
	uint16 TestSizes[] = {
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
	uint16 ExpectedChunkSize;
	uint16 ExpectedRemainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// Setting up offset values at the boundary of certificate length
	TestSizes[0] += (uint16)(TestSizes[0] + data_size);
	TestSizes[1] += (uint16)(TestSizes[1] + data_size);
	TestSizes[2] += (uint16)(TestSizes[2] + data_size);

	for (int i = 0; i < sizeof(TestSizes) / sizeof(TestSizes[0]); i++) {
		TEST_DEBUG_PRINT("i:%d TestSizes[i]=length:%u\n", i,
				 TestSizes[i]);
		m_spdm_get_certificate_request3.length = TestSizes[i];
		for (int j = 0; j < sizeof(TestSizes) / sizeof(TestSizes[0]);
		     j++) {
			TEST_DEBUG_PRINT("\tj:%d TestSizes[j]=Offset:%u\n", j,
					 TestSizes[j]);
			m_spdm_get_certificate_request3.Offset = TestSizes[j];

			// reseting an internal buffer to avoid overflow and prevent tests to succeed
			reset_managed_buffer(
				&spdm_context->transcript.message_b);
			response_size = sizeof(response);
			status = spdm_get_response_certificate(
				spdm_context,
				m_spdm_get_certificate_request3_size,
				&m_spdm_get_certificate_request3,
				&response_size, response);
			assert_int_equal(status, RETURN_SUCCESS);

			if (m_spdm_get_certificate_request3.Offset >=
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
				ExpectedChunkSize = (uint16)(MIN(
					m_spdm_get_certificate_request3.length,
					data_size -
						m_spdm_get_certificate_request3
							.Offset));
				ExpectedChunkSize =
					MIN(ExpectedChunkSize,
					    MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
				// Expected certificate length left
				ExpectedRemainder = (uint16)(
					data_size -
					m_spdm_get_certificate_request3.Offset -
					ExpectedChunkSize);

				assert_int_equal(
					response_size,
					sizeof(spdm_certificate_response_t) +
						ExpectedChunkSize);
				spdm_response = (void *)response;
				assert_int_equal(spdm_response->header
							 .request_response_code,
						 SPDM_CERTIFICATE);
				assert_int_equal(spdm_response->header.param1,
						 0);
				assert_int_equal(spdm_response->portion_length,
						 ExpectedChunkSize);
				assert_int_equal(
					spdm_response->remainder_length,
					ExpectedRemainder);
			}
		}
	}
	free(data);
}

/**
  Test 10: request MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of long certificate chains, with the largest valid Offset
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

	uint16 TestCases[] = { TEST_CERT_MAXINT16, TEST_CERT_MAXUINT16 };

	uintn ExpectedChunkSize;
	uintn ExpectedRemainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

	m_spdm_get_certificate_request3.length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

	for (int i = 0; i < sizeof(TestCases) / sizeof(TestCases[0]); i++) {
		read_responder_public_certificate_chain_by_size(
			m_use_hash_algo, m_use_asym_algo, TestCases[i], &data,
			&data_size, NULL, NULL);

		spdm_context->local_context.local_cert_chain_provision[0] =
			data;
		spdm_context->local_context.local_cert_chain_provision_size[0] =
			data_size;
		spdm_context->local_context.slot_count = 1;

		m_spdm_get_certificate_request3.Offset =
			(uint16)(MIN(data_size - 1, MAX_UINT16));
		TEST_DEBUG_PRINT("data_size: %u\n", data_size);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.Offset: %u\n",
				 m_spdm_get_certificate_request3.Offset);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.length: %u\n",
				 m_spdm_get_certificate_request3.length);
		TEST_DEBUG_PRINT(
			"Offset + length: %u\n",
			m_spdm_get_certificate_request3.Offset +
				m_spdm_get_certificate_request3.length);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		reset_managed_buffer(&spdm_context->transcript.message_b);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
		ExpectedChunkSize = (uint16)(MIN(
			m_spdm_get_certificate_request3.length,
			data_size - m_spdm_get_certificate_request3.Offset));
		ExpectedChunkSize =
			MIN(ExpectedChunkSize, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
		// Expected certificate length left
		ExpectedRemainder = (uint16)(
			data_size - m_spdm_get_certificate_request3.Offset -
			ExpectedChunkSize);

		TEST_DEBUG_PRINT("ExpectedChunkSize %u\n", ExpectedChunkSize);
		TEST_DEBUG_PRINT("ExpectedRemainder %u\n", ExpectedRemainder);

		if (ExpectedRemainder > MAX_UINT16 ||
		    ExpectedChunkSize > MAX_UINT16) {
			spdm_responseError = (void *)response;
			assert_int_equal(
				spdm_responseError->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(spdm_responseError->header.param1,
					 SPDM_ERROR_CODE_INVALID_REQUEST);
		} else {
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t) +
						 ExpectedChunkSize);
			spdm_response = (void *)response;
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 ExpectedChunkSize);
			assert_int_equal(spdm_response->remainder_length,
					 ExpectedRemainder);
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

	uint16 TestCases[] = { TEST_CERT_SMALL };

	uintn ExpectedChunkSize;
	uintn ExpectedRemainder;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

	m_spdm_get_certificate_request3.length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
	m_spdm_get_certificate_request3.Offset = 0;

	for (int i = 0; i < sizeof(TestCases) / sizeof(TestCases[0]); i++) {
		read_responder_public_certificate_chain_by_size(
			m_use_hash_algo, m_use_asym_algo, TestCases[i], &data,
			&data_size, NULL, NULL);
		spdm_context->local_context.local_cert_chain_provision[0] =
			data;
		spdm_context->local_context.local_cert_chain_provision_size[0] =
			data_size;
		spdm_context->local_context.slot_count = 1;

		TEST_DEBUG_PRINT("data_size: %u\n", data_size);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.Offset: %u\n",
				 m_spdm_get_certificate_request3.Offset);
		TEST_DEBUG_PRINT("m_spdm_get_certificate_request3.length: %u\n",
				 m_spdm_get_certificate_request3.length);
		TEST_DEBUG_PRINT(
			"Offset + length: %u\n",
			m_spdm_get_certificate_request3.Offset +
				m_spdm_get_certificate_request3.length);

		// reseting an internal buffer to avoid overflow and prevent tests to succeed
		reset_managed_buffer(&spdm_context->transcript.message_b);
		response_size = sizeof(response);
		status = spdm_get_response_certificate(
			spdm_context, m_spdm_get_certificate_request3_size,
			&m_spdm_get_certificate_request3, &response_size,
			response);
		assert_int_equal(status, RETURN_SUCCESS);

		// Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
		ExpectedChunkSize =
			MIN(m_spdm_get_certificate_request3.length,
			    data_size - m_spdm_get_certificate_request3.Offset);
		ExpectedChunkSize =
			MIN(ExpectedChunkSize, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
		// Expected certificate length left
		ExpectedRemainder = data_size -
				    m_spdm_get_certificate_request3.Offset -
				    ExpectedChunkSize;

		TEST_DEBUG_PRINT("ExpectedChunkSize %u\n", ExpectedChunkSize);
		TEST_DEBUG_PRINT("ExpectedRemainder %u\n", ExpectedRemainder);

		if (ExpectedRemainder > MAX_UINT16 ||
		    ExpectedChunkSize > MAX_UINT16) {
			spdm_responseError = (void *)response;
			assert_int_equal(
				spdm_responseError->header.request_response_code,
				SPDM_ERROR);
			assert_int_equal(spdm_responseError->header.param1,
					 SPDM_ERROR_CODE_INVALID_REQUEST);
		} else {
			assert_int_equal(response_size,
					 sizeof(spdm_certificate_response_t) +
						 ExpectedChunkSize);
			spdm_response = (void *)response;
			assert_int_equal(
				spdm_response->header.request_response_code,
				SPDM_CERTIFICATE);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 ExpectedChunkSize);
			assert_int_equal(spdm_response->remainder_length,
					 ExpectedRemainder);
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

	uintn count;
	uint16 ExpectedChunkSize;

	// Setting up the spdm_context and loading a sample certificate chain
	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_DIGESTS;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data,
						&data_size, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size;
	spdm_context->local_context.slot_count = 1;

	// This tests considers only length = 1
	m_spdm_get_certificate_request3.length = 1;
	ExpectedChunkSize = 1;

	count = (data_size + m_spdm_get_certificate_request3.length - 1) /
		m_spdm_get_certificate_request3.length;

	// reseting an internal buffer to avoid overflow and prevent tests to succeed
	reset_managed_buffer(&spdm_context->transcript.message_b);

	spdm_response = NULL;
	for (uintn offset = 0; offset < data_size; offset++) {
		TEST_DEBUG_PRINT("offset:%u \n", offset);
		m_spdm_get_certificate_request3.Offset = (uint16)offset;

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
						 ExpectedChunkSize);
			assert_int_equal(spdm_response->header.param1, 0);
			assert_int_equal(spdm_response->portion_length,
					 ExpectedChunkSize);
			assert_int_equal(spdm_response->remainder_length,
					 data_size - offset -
						 ExpectedChunkSize);
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
			assert_int_equal(
				spdm_context->transcript.message_b.buffer_size,
				sizeof(spdm_get_certificate_request_t) * count +
					sizeof(spdm_certificate_response_t) *
						count +
					data_size);
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
