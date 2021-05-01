/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

#define DEFAULT_SPDM_VERSION_ENTRY_COUNT 2

#pragma pack(1)
typedef struct {
	spdm_message_header_t header;
	uint8 reserved;
	uint8 version_number_entry_count;
	spdm_version_number_t version_number_entry[MAX_SPDM_VERSION_COUNT];
} spdm_version_response_mine_t;
#pragma pack()

spdm_get_version_request_t m_spdm_get_version_request1 = {
	{
		SPDM_MESSAGE_VERSION_10,
		SPDM_GET_VERSION,
	},
};
uintn m_spdm_get_version_request1_size = sizeof(m_spdm_get_version_request1);

spdm_get_version_request_t m_spdm_get_version_request2 = {
	{
		SPDM_MESSAGE_VERSION_10,
		SPDM_GET_VERSION,
	},
};
uintn m_spdm_get_version_request2_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

spdm_get_version_request_t m_spdm_get_version_request3 = {
	{
		SPDM_MESSAGE_VERSION_11,
		SPDM_GET_VERSION,
	},
};
uintn m_spdm_get_version_request3_size = sizeof(m_spdm_get_version_request3);

spdm_get_version_request_t m_spdm_get_version_request4 = {
	{
		SPDM_MESSAGE_VERSION_10,
		SPDM_VERSION,
	},
};
uintn m_spdm_get_version_request4_size = sizeof(m_spdm_get_version_request4);

/**
  Test 1: receiving a correct GET_VERSION from the requester.
  Expected behavior: the responder accepts the request and produces a valid VERSION
  response message.
**/
void test_spdm_responder_version_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request1_size,
					   &m_spdm_get_version_request1,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_version_response) +
				 DEFAULT_SPDM_VERSION_ENTRY_COUNT *
					 sizeof(spdm_version_number_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_VERSION);
}

/**
  Test 2: receiving a GET_VERSION message larger than specified (more parameters than the
  header), results in a correct VERSION message.
  Expected behavior: the responder refuses the GET_VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_version_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request2_size,
					   &m_spdm_get_version_request2,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

/**
  Test 3: receiving a correct GET_VERSION from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Buse state.
**/
void test_spdm_responder_version_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->response_state = SPDM_RESPONSE_STATE_BUSY;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request1_size,
					   &m_spdm_get_version_request1,
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
}

/**
  Test 4: receiving a correct GET_VERSION from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the requester resets the communication upon receiving the GET_VERSION
  message, fulfilling the resynchronization. A valid VERSION message is produced.
**/
void test_spdm_responder_version_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NEED_RESYNC;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request1_size,
					   &m_spdm_get_version_request1,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_version_response) +
				 DEFAULT_SPDM_VERSION_ENTRY_COUNT *
					 sizeof(spdm_version_number_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_VERSION);
	assert_int_equal(spdm_context->response_state,
			 SPDM_RESPONSE_STATE_NORMAL);
}

/**
  Test 5: receiving a correct GET_VERSION from the requester, but the responder could not
  produce the response in time.
  TODO: As from version 1.0.0, a GET_VERSION message should not receive an ERROR message
  indicating the ResponseNotReady. No timing parameters have been agreed yet.
**/
void test_spdm_responder_version_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;
	spdm_error_data_response_not_ready_t *error_data;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NOT_READY;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request1_size,
					   &m_spdm_get_version_request1,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size,
			 sizeof(spdm_error_response_t) +
				 sizeof(spdm_error_data_response_not_ready_t));
	spdm_response = (void *)response;
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
	assert_int_equal(error_data->request_code, SPDM_GET_VERSION);
}

/**
  Test 6: receiving a GET_VERSION message in SPDM version 1.1 (in the header), but correct
  1.0-version format.
  Expected behavior: the responder refuses the GET_VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_version_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->response_state = SPDM_RESPONSE_STATE_NORMAL;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request3_size,
					   &m_spdm_get_version_request3,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

/**
  Test 7: receiving a SPDM message with a VERSION 0x04 request_response_code instead
  of a GET_VERSION 0x84 one.
  Expected behavior: the responder refuses the VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void test_spdm_responder_version_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;
	uintn response_size;
	uint8 response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
	spdm_version_response *spdm_response;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;

	response_size = sizeof(response);
	status = spdm_get_response_version(spdm_context,
					   m_spdm_get_version_request3_size,
					   &m_spdm_get_version_request3,
					   &response_size, response);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(response_size, sizeof(spdm_error_response_t));
	spdm_response = (void *)response;
	assert_int_equal(spdm_response->header.request_response_code,
			 SPDM_ERROR);
	assert_int_equal(spdm_response->header.param1,
			 SPDM_ERROR_CODE_INVALID_REQUEST);
	assert_int_equal(spdm_response->header.param2, 0);
}

spdm_test_context_t m_spdm_responder_version_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	FALSE,
};

int spdm_responder_version_test_main(void)
{
	const struct CMUnitTest spdm_responder_version_tests[] = {
		cmocka_unit_test(test_spdm_responder_version_case1),
		// Invalid request
		cmocka_unit_test(test_spdm_responder_version_case2),
		// response_state: SPDM_RESPONSE_STATE_BUSY
		cmocka_unit_test(test_spdm_responder_version_case3),
		// response_state: SPDM_RESPONSE_STATE_NEED_RESYNC
		cmocka_unit_test(test_spdm_responder_version_case4),
		// response_state: SPDM_RESPONSE_STATE_NOT_READY
		cmocka_unit_test(test_spdm_responder_version_case5),
		// Invalid request
		cmocka_unit_test(test_spdm_responder_version_case6),
	};

	setup_spdm_test_context(&m_spdm_responder_version_test_context);

	return cmocka_run_group_tests(spdm_responder_version_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
