/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

spdm_challenge_request_t m_spdm_challenge_request1 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 0,
	  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request1_size = sizeof(m_spdm_challenge_request1);

spdm_challenge_request_t m_spdm_challenge_request2 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 0,
	  SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

spdm_challenge_request_t m_spdm_challenge_request3 = {
  { SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, MAX_SPDM_SLOT_COUNT,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request3_size = sizeof(m_spdm_challenge_request3);

spdm_challenge_request_t m_spdm_challenge_request4 = {
  { SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 1,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH },
};
uintn m_spdm_challenge_request4_size = sizeof(m_spdm_challenge_request4);

spdm_challenge_request_t    m_spdm_challenge_request5 = {
  { SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 0,
    SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH },
};
uintn m_spdm_challenge_request5_size = sizeof(m_spdm_challenge_request5);

spdm_challenge_request_t    m_spdm_challenge_request6 = {
  { SPDM_MESSAGE_VERSION_11, SPDM_CHALLENGE, 0,
    SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH },
};
uintn m_spdm_challenge_request6_size = sizeof(m_spdm_challenge_request6);

uint8 m_opaque_challenge_auth_rsp[9] = "openspdm";

/**
  Test 1: receiving a correct CHALLENGE message from the requester with
  no opaque data, no measurements, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;
	spdm_context->transcript.message_m.buffer_size =
		spdm_context->transcript.message_m.max_buffer_size;

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
	assert_int_equal(spdm_context->transcript.message_m.buffer_size,
					0);
	free(data1);
}

/**
  Test 2: receiving a CHALLENGE message larger than specified.
  Expected behavior: the responder refuses the CHALLENGE message and produces an
  ERROR message indicating the InvalidRequest.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;

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

/**
  Test 3: receiving a correct CHALLENGE from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Busy state.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;

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

/**
  Test 4: receiving a correct CHALLENGE from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the NeedResynch state.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;

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

/**
  Test 5: receiving a correct CHALLENGE from the requester, but the responder could not
  produce the response in time.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the ResponseNotReady state.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;

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

/**
  Test 6: receiving a correct CHALLENGE from the requester, but the responder is not set
  no receive a CHALLENGE message because previous messages (namely, GET_CAPABILITIES,
  NEGOTIATE_ALGORITHMS or GET_DIGESTS) have not been received.
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
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
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
	spdm_context->transcript.message_c.buffer_size = 0;

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

/**
  Test 7: receiving a correct CHALLENGE from the requester, but the responder does not
  have the challenge capability set.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void test_spdm_responder_challenge_auth_case7(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x7;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  // spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request1_size, &m_spdm_challenge_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
  assert_int_equal (spdm_response->header.param2, SPDM_CHALLENGE);
  free(data1);
}

/**
  Test 8: receiving an incorrect CHALLENGE from the requester, with the slot number
  larger than the specification limit.
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
void test_spdm_responder_challenge_auth_case8(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x8;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request3_size, &m_spdm_challenge_request3, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
  free(data1);
}

/**
  Test 9: eceiving a correct CHALLENGE message from the requester with
  no opaque data, no measurements, and slot number 1.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void test_spdm_responder_challenge_auth_case9(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x9;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[1] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[1] = data_size1;
  spdm_context->local_context.slot_count = 2;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request4_size, &m_spdm_challenge_request4, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + spdm_get_hash_size (m_use_hash_algo) + SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
  assert_int_equal (spdm_response->header.param1, 1);
  assert_int_equal (spdm_response->header.param2, 1 << 1);
  free(data1);
}

/**
  Test 10: receiving a correct CHALLENGE from the requester, but with certificate
  unavailable at the requested slot number (1).
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
void test_spdm_responder_challenge_auth_case10(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xA;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request3_size, &m_spdm_challenge_request3, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
  free(data1);
}

/**
  Test 11: receiving a correct CHALLENGE message from the requester with opaque 
  data as the bytes of the string "openspdm", no measurements, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void test_spdm_responder_challenge_auth_case11(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xB;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 8;
  spdm_context->local_context.opaque_challenge_auth_rsp = m_opaque_challenge_auth_rsp;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request1_size, &m_spdm_challenge_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + spdm_get_hash_size (m_use_hash_algo) + SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 8 + spdm_get_asym_signature_size (m_use_asym_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
  assert_int_equal (spdm_response->header.param1, 0);
  assert_int_equal (spdm_response->header.param2, 1 << 0);
  free(data1);
}

/**
  Test 12: receiving a correct CHALLENGE message from the requester with
  no opaque data, TCB measurement hash, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void test_spdm_responder_challenge_auth_case12(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xC;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request5_size, &m_spdm_challenge_request5, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + spdm_get_hash_size (m_use_hash_algo) + SPDM_NONCE_SIZE + spdm_get_hash_size (m_use_hash_algo) + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
  assert_int_equal (spdm_response->header.param1, 0);
  assert_int_equal (spdm_response->header.param2, 1 << 0);
  free(data1);
}

/**
  Test 13: receiving a correct CHALLENGE message from the requester with
  no opaque data, all measurement hashes, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void test_spdm_responder_challenge_auth_case13(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xD;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request6_size, &m_spdm_challenge_request6, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + spdm_get_hash_size (m_use_hash_algo) + SPDM_NONCE_SIZE + spdm_get_hash_size (m_use_hash_algo) + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
  assert_int_equal (spdm_response->header.param1, 0);
  assert_int_equal (spdm_response->header.param2, 1 << 0);
  free(data1);
}

/**
  Test 14: the responder does not have measurements capabilities, but
  receives a correct CHALLENGE message from the requester with
  no opaque data, all measurement hashes, and slot number 0.
  Expected behavior: the responder refuses the CHALLENGE message and produces an
  ERROR message indicating the UnsupportedRequest.
**/
void test_spdm_responder_challenge_auth_case14(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response;
  void                 *data1;
  uintn                data_size1;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xE;
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  // spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //no measurement capability
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data1, &data_size1, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data1;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;
  spdm_context->transcript.message_c.buffer_size = 0;

  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request1.nonce);
  status = spdm_get_response_challenge_auth (spdm_context, m_spdm_challenge_request6_size, &m_spdm_challenge_request6, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
  assert_int_equal (spdm_response->header.param2, SPDM_CHALLENGE);
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
		cmocka_unit_test(test_spdm_responder_challenge_auth_case7),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case8),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case9),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case10),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case11),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case12),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case13),
		cmocka_unit_test(test_spdm_responder_challenge_auth_case14),
	};

	setup_spdm_test_context(&m_spdm_responder_challenge_auth_test_context);

	return cmocka_run_group_tests(spdm_responder_challenge_auth_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
