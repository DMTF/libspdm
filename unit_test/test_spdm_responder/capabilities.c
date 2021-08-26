/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

spdm_get_capabilities_request m_spdm_get_capabilities_request1 = {
	{
		SPDM_MESSAGE_VERSION_10,
		SPDM_GET_CAPABILITIES,
	},
};
// version 1.0 message consists of only header (size 0x04).
// However, spdm_get_capabilities_request has a size of 0x0c.
// Therefore, sending a v1.0 request with this structure results in a wrong size request.
// size information was corrected to reflect the actual size of a get_capabilities 1.0 message.
uintn m_spdm_get_capabilities_request1_size = sizeof(spdm_message_header_t);

spdm_get_capabilities_request m_spdm_get_capabilities_request2 = {
	{
		SPDM_MESSAGE_VERSION_10,
		SPDM_GET_CAPABILITIES,
	},
};
uintn m_spdm_get_capabilities_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

spdm_get_capabilities_request m_spdm_get_capabilities_request3 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	0x12345678 //flags
};
uintn m_spdm_get_capabilities_request3_size =
	sizeof(m_spdm_get_capabilities_request3);

spdm_get_capabilities_request m_spdm_get_capabilities_request4 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request4_size =
	sizeof(m_spdm_get_capabilities_request4);

spdm_get_capabilities_request m_spdm_get_capabilities_request5 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(0x01 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request5_size =
	sizeof(m_spdm_get_capabilities_request5);

spdm_get_capabilities_request m_spdm_get_capabilities_request6 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request6_size =
	sizeof(m_spdm_get_capabilities_request6);

spdm_get_capabilities_request m_spdm_get_capabilities_request7 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request7_size =
	sizeof(m_spdm_get_capabilities_request7);

spdm_get_capabilities_request m_spdm_get_capabilities_request8 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(0x100000 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request8_size =
	sizeof(m_spdm_get_capabilities_request8);

spdm_get_capabilities_request m_spdm_get_capabilities_request9 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request9_size =
	sizeof(m_spdm_get_capabilities_request9);

spdm_get_capabilities_request m_spdm_get_capabilities_request10 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 //
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request10_size =
	sizeof(m_spdm_get_capabilities_request10);

spdm_get_capabilities_request m_spdm_get_capabilities_request11 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 //
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request11_size =
	sizeof(m_spdm_get_capabilities_request11);

spdm_get_capabilities_request m_spdm_get_capabilities_request12 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 //
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP
	 //
	 )
};
uintn m_spdm_get_capabilities_request12_size =
	sizeof(m_spdm_get_capabilities_request12);

spdm_get_capabilities_request m_spdm_get_capabilities_request13 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 //
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP
	 //
	 )
};
uintn m_spdm_get_capabilities_request13_size =
	sizeof(m_spdm_get_capabilities_request13);

spdm_get_capabilities_request m_spdm_get_capabilities_request14 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request14_size =
	sizeof(m_spdm_get_capabilities_request14);

spdm_get_capabilities_request m_spdm_get_capabilities_request15 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
uintn m_spdm_get_capabilities_request15_size =
	sizeof(m_spdm_get_capabilities_request15);

spdm_get_capabilities_request m_spdm_get_capabilities_request16 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request16_size =
	sizeof(m_spdm_get_capabilities_request16);

spdm_get_capabilities_request m_spdm_get_capabilities_request17 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	(SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //flags
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
	 //
	 //
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
	 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
uintn m_spdm_get_capabilities_request17_size =
	sizeof(m_spdm_get_capabilities_request17);

spdm_get_capabilities_request m_spdm_get_capabilities_request18 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_CAPABILITIES,
	}, //header
	0x00, //reserved
	0x01, //ct_exponent
	0x0000, //reserved, 2 bytes
	( // //flags
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
uintn m_spdm_get_capabilities_request18_size =
	sizeof(m_spdm_get_capabilities_request18);

void test_spdm_responder_capabilities_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;
	spdm_context->transcript.message_m.buffer_size =
		spdm_context->transcript.message_m.max_buffer_size;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request1_size,
		&m_spdm_get_capabilities_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_capabilities_response));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request1.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CAPABILITIES);
	assert_int_equal(spdm_context->transcript.message_m.buffer_size,
					0);
}

void test_spdm_responder_capabilities_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request2_size,
		&m_spdm_get_capabilities_request2, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request2.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request1_size,
		&m_spdm_get_capabilities_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request1.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_BUSY);
}

void test_spdm_responder_capabilities_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request1_size,
		&m_spdm_get_capabilities_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request1.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_REQUEST_RESYNCH);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NEED_RESYNC);
}

// According to spec, a responder shall not answer a get_capabilties with a ResponseNotReady
void test_spdm_responder_capabilities_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request1_size,
		&m_spdm_get_capabilities_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request1.header.spdm_version,
			 spdm_response->header.spdm_version);
	error_data =
		(spdm_error_data_response_not_ready_t *)(&spdm_response
								  ->reserved);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_RESPONSE_NOT_READY);
	assert_int_equal(spdm_response->header.param2, 0);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NOT_READY);
	assert_int_equal(error_data->request_code, SPDM_GET_CAPABILITIES);
}

void test_spdm_responder_capabilities_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request1_size,
		&m_spdm_get_capabilities_request1, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request1.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}
//New from here
void test_spdm_responder_capabilities_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	
	spdm_context->connection_info.version.major_version = 1;
	spdm_context->connection_info.version.minor_version = 1;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request3_size,
		&m_spdm_get_capabilities_request3, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request3.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request4_size,
		&m_spdm_get_capabilities_request4, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_capabilities_response));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request4.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CAPABILITIES);
}

void test_spdm_responder_capabilities_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request5_size,
		&m_spdm_get_capabilities_request5, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_capabilities_response));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request4.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CAPABILITIES);
}

void test_spdm_responder_capabilities_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xa;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request6_size,
		&m_spdm_get_capabilities_request6, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request6.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xb;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request7_size,
		&m_spdm_get_capabilities_request7, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request7.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xc;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request8_size,
		&m_spdm_get_capabilities_request8, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_capabilities_response));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request4.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CAPABILITIES);
}

void test_spdm_responder_capabilities_case13(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xd;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request9_size,
		&m_spdm_get_capabilities_request9, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request9.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case14(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xe;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request10_size,
		&m_spdm_get_capabilities_request10, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request10.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case15(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xf;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request11_size,
		&m_spdm_get_capabilities_request11, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request11.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case16(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x10;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request12_size,
		&m_spdm_get_capabilities_request12, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request12.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case17(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x11;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request13_size,
		&m_spdm_get_capabilities_request13, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request13.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case18(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x12;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	reset_managed_buffer(&spdm_context->transcript.message_a);

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request14_size,
		&m_spdm_get_capabilities_request14, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request14.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case19(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x13;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request15_size,
		&m_spdm_get_capabilities_request15, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request15.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case20(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x14;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request16_size,
		&m_spdm_get_capabilities_request16, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request16.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case21(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x15;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request17_size,
		&m_spdm_get_capabilities_request17, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request17.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

void test_spdm_responder_capabilities_case22(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_capabilities_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x16;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_VERSION;

	response_size = sizeof(response);
	status = spdm_get_response_capabilities(
		spdm_context, m_spdm_get_capabilities_request18_size,
		&m_spdm_get_capabilities_request18, &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_capabilities_response));
	spdm_response = (void *)response;
	assert_int_equal(m_spdm_get_capabilities_request18.header.spdm_version,
			 spdm_response->header.spdm_version);
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_CAPABILITIES);
}

spdm_test_context_t m_spdm_responder_capabilities_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_capabilities_test_main(void)
{
	const struct CMUnitTest spdm_responder_capabilities_tests[] = {
		// Success Case
		cmocka_unit_test(test_spdm_responder_capabilities_case1),
		// Bad request size
		cmocka_unit_test(test_spdm_responder_capabilities_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_capabilities_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_capabilities_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_capabilities_case5),
		// connection_state Check
		cmocka_unit_test(test_spdm_responder_capabilities_case6),
		// Invalid requester capabilities flag (random flag)
		cmocka_unit_test(test_spdm_responder_capabilities_case7),
		// V1.1 Success case, all possible flags set
		cmocka_unit_test(test_spdm_responder_capabilities_case8),
		// Requester capabilities flag bit 0 is set. reserved value should ne ignored
		cmocka_unit_test(test_spdm_responder_capabilities_case9),
		// meas_cap is set (meas_cap shall be cleared)
		cmocka_unit_test(test_spdm_responder_capabilities_case10),
		// meas_fresh_cap is set (meas_fresh_cap shall be cleared)
		cmocka_unit_test(test_spdm_responder_capabilities_case11),
		// Requester capabilities flag byte 2 bit 1 is set. reserved value should ne ignored
		cmocka_unit_test(test_spdm_responder_capabilities_case12),
		// pub_key_id_cap and cert_cap set (flags are mutually exclusive)
		cmocka_unit_test(test_spdm_responder_capabilities_case13),
		// encrypt_cap set and key_ex_cap and psk_cap cleared (encrypt_cap demands key_ex_cap or psk_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case14),
		// mac_cap set and key_ex_cap and psk_cap cleared (mac_cap demands key_ex_cap or psk_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case15),
		// key_ex_cap set and encrypt_cap and mac_cap cleared (key_ex_cap demands encrypt_cap or mac_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case16),
		// psk_cap set and encrypt_cap and mac_cap cleared (psk_cap demands encrypt_cap or mac_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case17),
		// encap_cap cleared and MUT_AUTH set (MUT_AUTH demands encap_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case18),
		// cert_cap set and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)
		cmocka_unit_test(test_spdm_responder_capabilities_case19),
		// key_ex_cap cleared and handshake_in_the_clear_cap set (handshake_in_the_clear_cap demands key_ex_cap to be set)
		cmocka_unit_test(test_spdm_responder_capabilities_case20),
		// encrypt_cap and mac_cap cleared and handshake_in_the_clear_cap set (handshake_in_the_clear_cap shall be cleared if encrypt_cap and mac_cap are cleared)
		cmocka_unit_test(test_spdm_responder_capabilities_case21),
		// cert_cap cleared and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)
		cmocka_unit_test(test_spdm_responder_capabilities_case22),
	};

	setup_spdm_test_context(&m_spdm_responder_capabilities_test_context);

	return cmocka_run_group_tests(spdm_responder_capabilities_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
