/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

#define MY_TEST_TOKEN            0x30
#define MY_WRONG_TEST_TOKEN      0x2F

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request1 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request1_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_CERTIFICATE,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request2_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request3 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_CHALLENGE,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request3_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request4 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_MEASUREMENTS,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request4_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request5 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_KEY_EXCHANGE,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request5_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request6 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_FINISH,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request6_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request7 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_PSK_EXCHANGE,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request7_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request8 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_PSK_FINISH,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request8_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request9 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request9_size = MAX_SPDM_MESSAGE_BUFFER_SIZE; //wrong size

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request10 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MY_WRONG_TEST_TOKEN //wrong token
  },
};
uintn m_spdm_respond_if_ready_request10_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t    m_spdm_respond_if_ready_request11 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_CERTIFICATE, //wrong original request code
    MY_TEST_TOKEN
  },
};
uintn m_spdm_respond_if_ready_request11_size = sizeof(spdm_message_header_t);

spdm_get_digest_request_t    m_spdm_get_digest_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_DIGESTS,
    0,
    0
  },
};
uintn m_spdm_get_digest_request_size = sizeof(spdm_message_header_t);

spdm_get_certificate_request_t    m_spdm_get_certificate_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CERTIFICATE,
    0,
    0
  },
  0,
  MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
uintn m_spdm_get_certificate_request_size = sizeof(m_spdm_get_certificate_request);

spdm_challenge_request_t    m_spdm_challenge_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
uintn m_spdm_challenge_request_size = sizeof(m_spdm_challenge_request);

spdm_get_measurements_request_t    m_spdm_get_measurements_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
  },
};
uintn m_spdm_get_measurements_request_size = sizeof(spdm_message_header_t);

#pragma pack(1)

typedef struct {
  spdm_message_header_t  header;
  uint16               req_session_id;
  uint16               reserved;
  uint8                random_data[SPDM_RANDOM_DATA_SIZE];
  uint8                exchange_data[MAX_DHE_KEY_SIZE];
  uint16               opaque_length;
  uint8                opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
} spdm_key_exchange_request_mine_t;

typedef struct {
  spdm_message_header_t  header;
  uint8                signature[MAX_ASYM_KEY_SIZE];
  uint8                verify_data[MAX_HASH_SIZE];
} spdm_finish_request_mine_t;

typedef struct {
  spdm_message_header_t  header;
  uint16               req_session_id;
  uint16               psk_hint_length;
  uint16               requester_context_length;
  uint16               opaque_length;
  uint8                psk_hint[MAX_SPDM_PSK_HINT_LENGTH];
  uint8                requester_context[DEFAULT_CONTEXT_LENGTH];
  uint8                opaque_data[MAX_SPDM_OPAQUE_DATA_SIZE];
} spdm_psk_exchange_request_mine_t;

typedef struct {
  spdm_message_header_t  header;
  uint8                verify_data[MAX_HASH_SIZE];
} spdm_psk_finish_request_mine_t;

#pragma pack()

spdm_key_exchange_request_mine_t    m_spdm_key_exchange_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_KEY_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
uintn m_spdm_key_exchange_request_size = sizeof(m_spdm_key_exchange_request);

spdm_finish_request_mine_t    m_spdm_finish_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_FINISH,
    0,
    0
  },
};
uintn m_spdm_finish_request_size = sizeof(m_spdm_finish_request);

spdm_psk_exchange_request_mine_t    m_spdm_psk_exchange_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
uintn m_spdm_psk_exchange_request_size = sizeof(m_spdm_psk_exchange_request);

spdm_psk_finish_request_mine_t    m_spdm_psk_finish_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_FINISH,
    0,
    0
  },
};
uintn m_spdm_psk_finish_request_size = sizeof(m_spdm_psk_finish_request);

spdm_end_session_request_t    m_spdm_end_session_request = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_END_SESSION,
    0,
    0
  }
};
uintn m_spdm_end_session_request_size = sizeof(m_spdm_end_session_request);

static uint8                  m_local_certificate_chain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

static void spdm_secured_message_set_request_finished_key(
	IN void *spdm_secured_message_context, IN void *key, IN uintn key_size)
{
	spdm_secured_message_context_t *secured_message_context;

	secured_message_context = spdm_secured_message_context;
	ASSERT(key_size == secured_message_context->hash_size);
	copy_mem(secured_message_context->handshake_secret.request_finished_key,
		 key, secured_message_context->hash_size);
}

/**
  Test 1: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_DIGESTS could not be processed.
  Expected behavior: the responder accepts the request and produces a valid DIGESTS
  response message.
**/
void test_spdm_responder_respond_if_ready_case1(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x1;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;

  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check DIGESTS response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request1_size, &m_spdm_respond_if_ready_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_digest_response_t) + spdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_DIGESTS);
}

/**
  Test 2: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_CERTIFICATE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid CERTIFICATE
  response message.
**/
void test_spdm_responder_respond_if_ready_case2(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_certificate_response_t *spdm_response; //response to the original request (CERTIFICATE)
  void                 *data;
  uintn                data_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x2;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_CERTIFICATE)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_DIGESTS;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->local_context.slot_count = 1;

  spdm_context->last_spdm_request_size = m_spdm_get_certificate_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_certificate_request, m_spdm_get_certificate_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_CERTIFICATE;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check CERTIFICATE response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request2_size, &m_spdm_respond_if_ready_request2, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_certificate_response_t) + MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CERTIFICATE);
  assert_int_equal (spdm_response->header.param1, 0);
  assert_int_equal (spdm_response->portion_length, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  assert_int_equal (spdm_response->remainder_length, data_size - MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  free(data);
}

/**
  Test 3: receiving a correct RESPOND_IF_READY from the requester, after a 
  CHALLENGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid CHALLENGE_AUTH
  response message.
**/
void test_spdm_responder_respond_if_ready_case3(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_challenge_auth_response_t *spdm_response; //response to the original request (CHALLENGE_AUTH)
  void                 *data;
  uintn                data_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x3;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (CHALLENGE)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.opaque_challenge_auth_rsp_size = 0;

  spdm_context->last_spdm_request_size = m_spdm_challenge_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_challenge_request, m_spdm_challenge_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_CHALLENGE;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check CHALLENGE response
  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_challenge_request.nonce);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request3_size, &m_spdm_respond_if_ready_request3, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + spdm_get_hash_size (m_use_hash_algo) + SPDM_NONCE_SIZE + 0 + sizeof(uint16) + 0 + spdm_get_asym_signature_size (m_use_asym_algo));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
  assert_int_equal (spdm_response->header.param1, 0);
  assert_int_equal (spdm_response->header.param2, 1 << 0);
  free(data);
}

/**
  Test 4: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_MEASUREMENTS could not be processed.
  Expected behavior: the responder accepts the request and produces a valid MEASUREMENTS
  response message.
**/
void test_spdm_responder_respond_if_ready_case4(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_measurements_response_t *spdm_response; //response to the original request (MEASUREMENTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x4;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_MEASUREMENTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  spdm_context->local_context.opaque_measurement_rsp_size = 0;
  spdm_context->local_context.opaque_measurement_rsp = NULL;

  spdm_context->last_spdm_request_size = m_spdm_get_measurements_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_measurements_request, m_spdm_get_measurements_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_MEASUREMENTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check MEASUREMENT response
  response_size = sizeof(response);
  spdm_get_random_number (SPDM_NONCE_SIZE, m_spdm_get_measurements_request.nonce);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request4_size, &m_spdm_respond_if_ready_request4, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_measurements_response_t) + sizeof(uint16) + SPDM_NONCE_SIZE);
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_MEASUREMENTS);
  assert_int_equal (spdm_response->header.param1, MEASUREMENT_BLOCK_NUMBER);
}

/**
  Test 5: receiving a correct RESPOND_IF_READY from the requester, after a 
  KEY_EXCHANGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid KEY_EXCHANGE_RSP
  response message.
**/
void test_spdm_responder_respond_if_ready_case5(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_key_exchange_response_t *spdm_response; //response to the original request (KEY_EXCHANGE_RSP)
  void                 *data;
  uintn                data_size;
  uint8                *ptr;
  uintn                dhe_key_size;
  void                 *dhe_context;
  uintn                opaque_key_exchange_req_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x5;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (KEY_EXCHANGE)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.mut_auth_requested = 0;

  m_spdm_key_exchange_request.req_session_id = 0xFFFF;
  m_spdm_key_exchange_request.reserved = 0;
  ptr = m_spdm_key_exchange_request.random_data;
  spdm_get_random_number (SPDM_RANDOM_DATA_SIZE, ptr);
  ptr += SPDM_RANDOM_DATA_SIZE;
  dhe_key_size = spdm_get_dhe_pub_key_size (m_use_dhe_algo);
  dhe_context = spdm_dhe_new (m_use_dhe_algo);
  spdm_dhe_generate_key (m_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
  ptr += dhe_key_size;
  spdm_dhe_free (m_use_dhe_algo, dhe_context);
  opaque_key_exchange_req_size = spdm_get_opaque_data_supported_version_data_size (spdm_context);
  *(uint16 *)ptr = (uint16)opaque_key_exchange_req_size;
  ptr += sizeof(uint16);
  spdm_build_opaque_data_supported_version_data (spdm_context, &opaque_key_exchange_req_size, ptr);
  ptr += opaque_key_exchange_req_size;

  spdm_context->last_spdm_request_size = m_spdm_key_exchange_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_key_exchange_request, m_spdm_key_exchange_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_KEY_EXCHANGE;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check KEY_EXCHANGE_RSP response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request5_size, &m_spdm_respond_if_ready_request5, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_key_exchange_response_t) + dhe_key_size + 2 + spdm_get_opaque_data_version_selection_data_size(spdm_context) + spdm_get_asym_signature_size (m_use_asym_algo) + spdm_get_hash_size (m_use_hash_algo));
  assert_int_equal (spdm_secured_message_get_session_state (spdm_context->session_info[0].secured_message_context), SPDM_SESSION_STATE_HANDSHAKING);
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
  assert_int_equal (spdm_response->rsp_session_id, 0xFFFF);
  free(data);
  spdm_free_session_id (spdm_context, (0xFFFFFFFF));
}

/**
  Test 6: receiving a correct RESPOND_IF_READY from the requester, after a 
  FINISH could not be processed.
  Expected behavior: the responder accepts the request and produces a valid FINISH_RSP
  response message.
**/
void test_spdm_responder_respond_if_ready_case6(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_finish_response_t *spdm_response; //response to the original request (FINISH_RSP)
  void                 *data;
  uintn                data_size;
  uint8                *ptr;
  uint8                dummy_buffer[MAX_HASH_SIZE];
  uint8                *cert_buffer;
  uintn                cert_buffer_size;
  uint8                cert_buffer_hash[MAX_HASH_SIZE];
  large_managed_buffer_t th_curr;
  uint8                request_finished_key[MAX_HASH_SIZE];
  spdm_session_info_t    *session_info;
  uint32               session_id;
  uint32               hash_size;
  uint32               hmac_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x6;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (FINISH)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->connection_info.local_used_cert_chain_buffer = data;
  spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.mut_auth_requested = 0;

  session_id = 0xFFFFFFFF;
  spdm_context->latest_session_id = session_id;
  session_info = &spdm_context->session_info[0];
  spdm_session_info_init (spdm_context, session_info, session_id, FALSE);
  hash_size = spdm_get_hash_size (m_use_hash_algo);
  set_mem (dummy_buffer, hash_size, (uint8)(0xFF));
  spdm_secured_message_set_request_finished_key (session_info->secured_message_context, dummy_buffer, hash_size);
  spdm_secured_message_set_session_state (session_info->secured_message_context, SPDM_SESSION_STATE_HANDSHAKING);

  hash_size = spdm_get_hash_size (m_use_hash_algo);
  hmac_size = spdm_get_hash_size (m_use_hash_algo);
  ptr = m_spdm_finish_request.signature;
  init_managed_buffer (&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  cert_buffer = (uint8 *)data + sizeof(spdm_cert_chain_t) + hash_size;
  cert_buffer_size = data_size - (sizeof(spdm_cert_chain_t) + hash_size);
  spdm_hash_all (m_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
  // Transcript.MessageA size is 0
  append_managed_buffer (&th_curr, cert_buffer_hash, hash_size);
  // SessionTranscript.MessageK is 0 
  append_managed_buffer (&th_curr, (uint8 *)&m_spdm_finish_request, sizeof(spdm_finish_request_t));
  set_mem (request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
  spdm_hmac_all (m_use_hash_algo, get_managed_buffer(&th_curr), get_managed_buffer_size(&th_curr), request_finished_key, hash_size, ptr);

  spdm_context->last_spdm_request_size = sizeof(spdm_finish_request_t) + hmac_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_finish_request, m_spdm_finish_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_FINISH;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check FINISH_RSP response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request6_size, &m_spdm_respond_if_ready_request6, &response_size, response);
  // status = SpdmGetResponseFinish (spdm_context, mSpdmFinishRequest1_size, &mSpdmFinishRequest1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_finish_response_t) + hmac_size);
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_FINISH_RSP);
  free(data);
  spdm_free_session_id (spdm_context, (0xFFFFFFFF));
}

/**
  Test 7: receiving a correct RESPOND_IF_READY from the requester, after a 
  PSK_EXCHANGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid PSK_EXCHANGE_RSP
  response message.
**/
void test_spdm_responder_respond_if_ready_case7(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_psk_exchange_response_t *spdm_response; //response to the original request (PSK_EXCHANGE_RSP)
  void                 *data;
  uintn                data_size;
  uint8                *ptr;
  static uint8         local_psk_hint[32];
  uintn                OpaquePskExchangeReqSize;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x7;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (PSK_EXCHANGE)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
  spdm_context->connection_info.algorithm.key_schedule = m_use_key_schedule_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->connection_info.local_used_cert_chain_buffer = data;
  spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;
  spdm_context->local_context.slot_count = 1;
  zero_mem (local_psk_hint, 32);
  copy_mem (&local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
  spdm_context->local_context.psk_hint = local_psk_hint;

  m_spdm_psk_exchange_request.psk_hint_length = (uint16)spdm_context->local_context.psk_hint_size;
  m_spdm_psk_exchange_request.requester_context_length = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = spdm_get_opaque_data_supported_version_data_size (spdm_context);
  m_spdm_psk_exchange_request.opaque_length = (uint16)OpaquePskExchangeReqSize;
  m_spdm_psk_exchange_request.req_session_id = 0xFFFF;
  ptr = m_spdm_psk_exchange_request.psk_hint;
  copy_mem (ptr, spdm_context->local_context.psk_hint, spdm_context->local_context.psk_hint_size);
  ptr += m_spdm_psk_exchange_request.psk_hint_length;
  spdm_get_random_number (DEFAULT_CONTEXT_LENGTH, ptr);
  ptr += m_spdm_psk_exchange_request.requester_context_length;
  spdm_build_opaque_data_supported_version_data (spdm_context, &OpaquePskExchangeReqSize, ptr);
  ptr += OpaquePskExchangeReqSize;

  spdm_context->last_spdm_request_size = m_spdm_psk_exchange_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_psk_exchange_request, m_spdm_psk_exchange_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_PSK_EXCHANGE;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check PSK_EXCHANGE_RSP response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request7_size, &m_spdm_respond_if_ready_request7, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_psk_exchange_response_t) + DEFAULT_CONTEXT_LENGTH + spdm_get_opaque_data_version_selection_data_size(spdm_context) + spdm_get_hash_size (m_use_hash_algo));
  assert_int_equal (spdm_secured_message_get_session_state (spdm_context->session_info[0].secured_message_context), SPDM_SESSION_STATE_HANDSHAKING);
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_PSK_EXCHANGE_RSP);
  assert_int_equal (spdm_response->rsp_session_id, 0xFFFF);
  free(data);
  spdm_free_session_id (spdm_context, (0xFFFFFFFF));
}

/**
  Test 8: receiving a correct RESPOND_IF_READY from the requester, after a 
  PSK_FINISH could not be processed.
  Expected behavior: the responder accepts the request and produces a valid PSK_FINISH_RSP
  response message.
**/
void test_spdm_responder_respond_if_ready_case8(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_psk_finish_response_t *spdm_response; //response to the original request (FINISH_PSK_RSP)
  void                 *data;
  uintn                data_size;
  uint8                *ptr;
  uint8                local_psk_hint[32];
  uint8                dummy_buffer[MAX_HASH_SIZE];
  large_managed_buffer_t th_curr;
  uint8                request_finished_key[MAX_HASH_SIZE];
  spdm_session_info_t    *session_info;
  uint32               session_id;
  uint32               hash_size;
  uint32               hmac_size;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x8;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (FINISH)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_AUTHENTICATED;
  spdm_context->local_context.capability.flags = 0;
  spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->connection_info.algorithm.base_asym_algo = m_use_asym_algo;
  spdm_context->connection_info.algorithm.measurement_spec = m_use_measurement_spec;
  spdm_context->connection_info.algorithm.measurement_hash_algo = m_use_measurement_hash_algo;
  spdm_context->connection_info.algorithm.dhe_named_group = m_use_dhe_algo;
  spdm_context->connection_info.algorithm.aead_cipher_suite = m_use_aead_algo;
  
  spdm_context->connection_info.version.major_version = 1;
  spdm_context->connection_info.version.minor_version = 1;
  read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  spdm_context->local_context.local_cert_chain_provision[0] = data;
  spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
  spdm_context->connection_info.local_used_cert_chain_buffer = data;
  spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;
  spdm_context->local_context.slot_count = 1;
  spdm_context->local_context.mut_auth_requested = 0;
  zero_mem (local_psk_hint, 32);
  copy_mem (&local_psk_hint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  spdm_context->local_context.psk_hint_size = sizeof(TEST_PSK_HINT_STRING);
  spdm_context->local_context.psk_hint = local_psk_hint;

  session_id = 0xFFFFFFFF;
  spdm_context->latest_session_id = session_id;
  spdm_context->last_spdm_request_session_id_valid = TRUE;
  spdm_context->last_spdm_request_session_id = session_id;
  session_info = &spdm_context->session_info[0];
  spdm_session_info_init (spdm_context, session_info, session_id, FALSE);
  hash_size = spdm_get_hash_size (m_use_hash_algo);
  set_mem (dummy_buffer, hash_size, (uint8)(0xFF));
  spdm_secured_message_set_request_finished_key (session_info->secured_message_context, dummy_buffer, hash_size);
  spdm_secured_message_set_session_state (session_info->secured_message_context, SPDM_SESSION_STATE_HANDSHAKING);

  hash_size = spdm_get_hash_size (m_use_hash_algo);
  hmac_size = spdm_get_hash_size (m_use_hash_algo);
  ptr = m_spdm_psk_finish_request.verify_data;
  init_managed_buffer (&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  // Transcript.MessageA size is 0
  // SessionTranscript.MessageK is 0 
  append_managed_buffer (&th_curr, (uint8 *)&m_spdm_psk_finish_request, sizeof(spdm_psk_finish_request_t));
  set_mem (request_finished_key, MAX_HASH_SIZE, (uint8)(0xFF));
  spdm_hmac_all (m_use_hash_algo, get_managed_buffer(&th_curr), get_managed_buffer_size(&th_curr), request_finished_key, hash_size, ptr);

  spdm_context->last_spdm_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_psk_finish_request, m_spdm_psk_finish_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_PSK_FINISH;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check FINISH_PSK_RSP response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request8_size, &m_spdm_respond_if_ready_request8, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_psk_finish_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_PSK_FINISH_RSP);
  free(data);
  spdm_free_session_id (spdm_context, (0xFFFFFFFF));
}

/**
  Test 9: receiving a RESPOND_IF_READY message larger than specified (more parameters 
  than the header), after a GET_DIGESTS could not be processed.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_respond_if_ready_case9(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0x9;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request9_size, &m_spdm_respond_if_ready_request9, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

/**
  Test 10: receiving a correct RESPOND_IF_READY from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Busy state.
**/
void test_spdm_responder_respond_if_ready_case10(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xA;
  spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request1_size, &m_spdm_respond_if_ready_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (spdm_response->header.param2, 0);
  assert_int_equal (spdm_context->response_state, SPDM_RESPONSE_STATE_BUSY);
}

/**
  Test 11: receiving a correct RESPOND_IF_READY from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the NeedResynch state.
**/
void test_spdm_responder_respond_if_ready_case11(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xB;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request1_size, &m_spdm_respond_if_ready_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (spdm_response->header.param2, 0);
  assert_int_equal (spdm_context->response_state, SPDM_RESPONSE_STATE_NEED_RESYNC);
}

/**
  Test 12: receiving a correct RESPOND_IF_READY from the requester, but the responder could not
  produce the response in time.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the ResponseNotReady state, with the same token as the request.
**/
void test_spdm_responder_respond_if_ready_case12(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)
  spdm_error_data_response_not_ready_t *error_data;

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xC;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request1_size, &m_spdm_respond_if_ready_request1, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t) + sizeof(spdm_error_data_response_not_ready_t));
  spdm_response = (void *)response;
  error_data = (spdm_error_data_response_not_ready_t*)(spdm_response + 1);
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (spdm_response->header.param2, 0);
  assert_int_equal (spdm_context->response_state, SPDM_RESPONSE_STATE_NOT_READY);
  assert_int_equal (error_data->request_code, SPDM_GET_DIGESTS);
  assert_int_equal (error_data->token, MY_TEST_TOKEN);
}

/**
  Test 13: receiving a correct RESPOND_IF_READY from the requester, with the correct original
  request code, but with a token different from the expected.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_respond_if_ready_case13(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xD;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request10_size, &m_spdm_respond_if_ready_request10, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

/**
  Test 14: receiving a correct RESPOND_IF_READY from the requester, with the correct token, 
  but with a request code different from the expected.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_respond_if_ready_case14(void **state) {
  return_status        status;
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  spdm_digest_response_t *spdm_response; //response to the original request (DIGESTS)

  spdm_test_context = *state;
  spdm_context = spdm_test_context->spdm_context;
  spdm_test_context->case_id = 0xE;
  spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

  //state for the the original request (GET_DIGESTS)
  spdm_context->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED; 
  spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  spdm_context->connection_info.algorithm.base_hash_algo = m_use_hash_algo;
  spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
  spdm_context->local_context.local_cert_chain_provision_size[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  set_mem (m_local_certificate_chain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (uint8)(0xFF));
  spdm_context->local_context.slot_count = 1;
  spdm_context->last_spdm_request_size = m_spdm_get_digest_request_size;
  copy_mem (spdm_context->last_spdm_request, &m_spdm_get_digest_request, m_spdm_get_digest_request_size);

  //RESPOND_IF_READY specific data
  spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
  copy_mem (spdm_context->cache_spdm_request, spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
  spdm_context->error_data.rd_exponent = 1;
  spdm_context->error_data.rd_tm        = 1;
  spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
  spdm_context->error_data.token       = MY_TEST_TOKEN;

  //check ERROR response
  response_size = sizeof(response);
  status = spdm_get_response_respond_if_ready(spdm_context, m_spdm_respond_if_ready_request11_size, &m_spdm_respond_if_ready_request11, &response_size, response);
  assert_int_equal (status, RETURN_SUCCESS);
  assert_int_equal (response_size, sizeof(spdm_error_response_t));
  spdm_response = (void *)response;
  assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
  assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (spdm_response->header.param2, 0);
}

spdm_test_context_t       m_spdm_responder_respond_if_ready_test_context = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int spdm_responder_respond_if_ready_test_main(void) {
  const struct CMUnitTest spdm_responder_respond_if_ready_tests[] = {
    // Success Case
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case1),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case2),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case3),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case4),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case5),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case6),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case7),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case8),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case9),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case10),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case11),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case12),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case13),
    cmocka_unit_test(test_spdm_responder_respond_if_ready_case14),
  };

  setup_spdm_test_context (&m_spdm_responder_respond_if_ready_test_context);

  return cmocka_run_group_tests(spdm_responder_respond_if_ready_tests, spdm_unit_test_group_setup, spdm_unit_test_group_teardown);
}
