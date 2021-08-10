/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

#pragma pack(1)

typedef struct {
	spdm_message_header_t header;
	uint8 signature[MAX_ASYM_KEY_SIZE];
	uint8 verify_data[MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

#pragma pack()

spdm_finish_request_mine_t m_spdm_finish_request1 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request1_size = sizeof(m_spdm_finish_request1);

spdm_finish_request_mine_t m_spdm_finish_request2 = {
	{ SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
uintn m_spdm_finish_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

uint8 m_dummy_buffer[MAX_HASH_SIZE];

void spdm_secured_message_set_request_finished_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->hash_size);
	copy_mem(secured_message_context->handshake_secret.request_finished_key,
		 key, secured_message_context->hash_size);
}

void test_spdm_responder_finish_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_finish_response_t) + hmac_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_FINISH_RSP);
	free(data1);
}

void test_spdm_responder_finish_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request2.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request2,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request2_size,
					  &m_spdm_finish_request2,
					  &response_size, response);
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

void test_spdm_responder_finish_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
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

void test_spdm_responder_finish_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
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

void test_spdm_responder_finish_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
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
	assert_int_equal(error_data->request_code, SPDM_FINISH);
	free(data1);
}

void test_spdm_responder_finish_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
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

void test_spdm_responder_finish_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_finish_response_t *spdm_response;
	void *data1;
	uintn data_size1;
	uint8 *ptr;
	uint8 *cert_buffer;
	uintn cert_buffer_size;
	uint8 cert_buffer_hash[MAX_HASH_SIZE];
	large_managed_buffer_t th_curr;
	uint8 request_finished_key[MAX_HASH_SIZE];
	spdm_session_info_t *session_info;
	uint32 session_id;
	uint32 hash_size;
	uint32 hmac_size;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
	spdm_context->connection_info.algorithm.base_hash_algo =
		m_use_hash_algo;
	spdm_context->connection_info.algorithm.base_asym_algo =
		m_use_asym_algo;
	spdm_context->connection_info.algorithm.measurement_spec =
		m_use_measurement_spec;
	spdm_context->connection_info.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->connection_info.algorithm.dhe_named_group =
		m_use_dhe_algo;
	spdm_context->connection_info.algorithm.aead_cipher_suite =
		m_use_aead_algo;
	read_responder_public_certificate_chain(m_use_hash_algo,
						m_use_asym_algo, &data1,
						&data_size1, NULL, NULL);
	spdm_context->local_context.local_cert_chain_provision[0] = data1;
	spdm_context->local_context.local_cert_chain_provision_size[0] =
		data_size1;
	spdm_context->connection_info.local_used_cert_chain_buffer = data1;
	spdm_context->connection_info.local_used_cert_chain_buffer_size =
		data_size1;
	spdm_context->local_context.slot_count = 1;
	spdm_context->transcript.message_a.buffer_size = 0;
	spdm_context->local_context.mut_auth_requested = 0;

	session_id = 0xFFFFFFFF;
	spdm_context->latest_session_id = session_id;
	session_info = &spdm_context->session_info[0];
	spdm_session_info_init(spdm_context, session_info, session_id, FALSE);
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	set_mem(m_dummy_buffer, hash_size, (uint8)(0xFF));
	spdm_secured_message_set_request_finished_key(
		session_info->secured_message_context, m_dummy_buffer,
		hash_size);
	spdm_secured_message_set_session_state(
		session_info->secured_message_context,
		SPDM_SESSION_STATE_HANDSHAKING);

	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
	hash_size = spdm_get_hash_size(m_use_hash_algo);
	hmac_size = spdm_get_hash_size(m_use_hash_algo);
	ptr = m_spdm_finish_request1.signature;
	init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
	cert_buffer = (uint8 *)data1 + sizeof(spdm_cert_chain_t) + hash_size;
	cert_buffer_size = data_size1 - (sizeof(spdm_cert_chain_t) + hash_size);
	spdm_context->transcript.message_m.buffer_size =
							spdm_context->transcript.message_m.max_buffer_size;
	spdm_context->transcript.message_b.buffer_size =
							spdm_context->transcript.message_b.max_buffer_size;
	spdm_context->transcript.message_c.buffer_size =
							spdm_context->transcript.message_c.max_buffer_size;
	spdm_context->transcript.message_mut_b.buffer_size =
							spdm_context->transcript.message_mut_b.max_buffer_size;
	spdm_context->transcript.message_mut_c.buffer_size =
							spdm_context->transcript.message_mut_c.max_buffer_size;

	spdm_hash_all(m_use_hash_algo, cert_buffer, cert_buffer_size,
		      cert_buffer_hash);
	// transcript.message_a size is 0
	append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
	// session_transcript.message_k is 0
	append_managed_buffer(&th_curr, (uint8 *)&m_spdm_finish_request1,
			      sizeof(spdm_finish_request_t));
	set_mem(request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
	spdm_hmac_all(m_use_hash_algo, get_managed_buffer(&th_curr),
		      get_managed_buffer_size(&th_curr), request_finished_key,
		      hash_size, ptr);
	m_spdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
	response_size = sizeof(response);
	status = spdm_get_response_finish(spdm_context,
					  m_spdm_finish_request1_size,
					  &m_spdm_finish_request1,
					  &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_finish_response_t) + hmac_size);
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_FINISH_RSP);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
	assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);

	free(data1);
}

spdm_test_context_t m_spdm_responder_finish_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_finish_test_main(void)
{
	const struct CMUnitTest spdm_responder_finish_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_finish_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_finish_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_finish_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_finish_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_finish_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_finish_case6),
		// Buffer reset
		cmocka_unit_test(test_spdm_responder_finish_case7),
	};

	setup_spdm_test_context(&m_spdm_responder_finish_test_context);

	return cmocka_run_group_tests(spdm_responder_finish_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
