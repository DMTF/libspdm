/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

return_status spdm_requester_negotiate_algorithms_test_send_message(
	IN void *spdm_context, IN uintn request_size, IN void *request,
	IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;
	case 0x2:
		return RETURN_SUCCESS;
	case 0x3:
		return RETURN_SUCCESS;
	case 0x4:
		return RETURN_SUCCESS;
	case 0x5:
		return RETURN_SUCCESS;
	case 0x6:
		return RETURN_SUCCESS;
	case 0x7:
		return RETURN_SUCCESS;
	case 0x8:
		return RETURN_SUCCESS;
	case 0x9:
		return RETURN_SUCCESS;
	case 0xA:
		return RETURN_SUCCESS;
	case 0xB:
		return RETURN_SUCCESS;
	case 0xC:
		return RETURN_SUCCESS;
	default:
		return RETURN_DEVICE_ERROR;
	}
}

return_status spdm_requester_negotiate_algorithm_test_receive_message(
	IN void *spdm_context, IN OUT uintn *response_size,
	IN OUT void *response, IN uint64 timeout)
{
	spdm_test_context_t *spdm_test_context;

	spdm_test_context = get_spdm_test_context();
	switch (spdm_test_context->case_id) {
	case 0x1:
		return RETURN_DEVICE_ERROR;

	case 0x2: {
		spdm_algorithms_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ALGORITHMS;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.length = sizeof(spdm_algorithms_response_t);
		spdm_response.measurement_specification_sel =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		spdm_response.measurement_hash_algo =
			m_use_measurement_hash_algo;
		spdm_response.base_asym_sel = m_use_asym_algo;
		spdm_response.base_hash_sel = m_use_hash_algo;
		spdm_response.ext_asym_sel_count = 0;
		spdm_response.ext_hash_sel_count = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x3: {
		spdm_algorithms_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ALGORITHMS;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.length = sizeof(spdm_algorithms_response_t);
		spdm_response.measurement_specification_sel =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		spdm_response.measurement_hash_algo =
			m_use_measurement_hash_algo;
		spdm_response.base_asym_sel = m_use_asym_algo;
		spdm_response.base_hash_sel = m_use_hash_algo;
		spdm_response.ext_asym_sel_count = 0;
		spdm_response.ext_hash_sel_count = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x4: {
		spdm_error_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x5: {
		spdm_error_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x6: {
		static uintn sub_index1 = 0;
		if (sub_index1 == 0) {
			spdm_error_response_t spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
			spdm_response.header.param2 = 0;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index1 == 1) {
			spdm_algorithms_response_t spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code =
				SPDM_ALGORITHMS;
			spdm_response.header.param1 = 0;
			spdm_response.header.param2 = 0;
			spdm_response.length =
				sizeof(spdm_algorithms_response_t);
			spdm_response.measurement_specification_sel =
				SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
			spdm_response.measurement_hash_algo =
				m_use_measurement_hash_algo;
			spdm_response.base_asym_sel = m_use_asym_algo;
			spdm_response.base_hash_sel = m_use_hash_algo;
			spdm_response.ext_asym_sel_count = 0;
			spdm_response.ext_hash_sel_count = 0;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		}
		sub_index1++;
	}
		return RETURN_SUCCESS;

	case 0x7: {
		spdm_error_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
		spdm_response.header.param2 = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x8: {
		spdm_error_response_data_response_not_ready_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ERROR;
		spdm_response.header.param1 =
			SPDM_ERROR_CODE_RESPONSE_NOT_READY;
		spdm_response.header.param2 = 0;
		spdm_response.extend_error_data.rd_exponent = 1;
		spdm_response.extend_error_data.rd_tm = 1;
		spdm_response.extend_error_data.request_code =
			SPDM_NEGOTIATE_ALGORITHMS;
		spdm_response.extend_error_data.token = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0x9: {
		static uintn sub_index2 = 0;
		if (sub_index2 == 0) {
			spdm_error_response_data_response_not_ready_t
				spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code = SPDM_ERROR;
			spdm_response.header.param1 =
				SPDM_ERROR_CODE_RESPONSE_NOT_READY;
			spdm_response.header.param2 = 0;
			spdm_response.extend_error_data.rd_exponent = 1;
			spdm_response.extend_error_data.rd_tm = 1;
			spdm_response.extend_error_data.request_code =
				SPDM_NEGOTIATE_ALGORITHMS;
			spdm_response.extend_error_data.token = 1;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		} else if (sub_index2 == 1) {
			spdm_algorithms_response_t spdm_response;

			zero_mem(&spdm_response, sizeof(spdm_response));
			spdm_response.header.spdm_version =
				SPDM_MESSAGE_VERSION_10;
			spdm_response.header.request_response_code =
				SPDM_ALGORITHMS;
			spdm_response.header.param1 = 0;
			spdm_response.header.param2 = 0;
			spdm_response.length =
				sizeof(spdm_algorithms_response_t);
			spdm_response.measurement_specification_sel =
				SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
			spdm_response.measurement_hash_algo =
				m_use_measurement_hash_algo;
			spdm_response.base_asym_sel = m_use_asym_algo;
			spdm_response.base_hash_sel = m_use_hash_algo;
			spdm_response.ext_asym_sel_count = 0;
			spdm_response.ext_hash_sel_count = 0;

			spdm_transport_test_encode_message(
				spdm_context, NULL, FALSE, FALSE,
				sizeof(spdm_response), &spdm_response,
				response_size, response);
		}
		sub_index2++;
	}
		return RETURN_SUCCESS;

	case 0xA: {
		spdm_algorithms_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ALGORITHMS;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.length = sizeof(spdm_algorithms_response_t);
		spdm_response.measurement_specification_sel =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		spdm_response.measurement_hash_algo = 0;
		spdm_response.base_asym_sel = m_use_asym_algo;
		spdm_response.base_hash_sel = m_use_hash_algo;
		spdm_response.ext_asym_sel_count = 0;
		spdm_response.ext_hash_sel_count = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xB: {
		spdm_algorithms_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ALGORITHMS;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.length = sizeof(spdm_algorithms_response_t);
		spdm_response.measurement_specification_sel =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		spdm_response.measurement_hash_algo =
			m_use_measurement_hash_algo;
		spdm_response.base_asym_sel = 0;
		spdm_response.base_hash_sel = m_use_hash_algo;
		spdm_response.ext_asym_sel_count = 0;
		spdm_response.ext_hash_sel_count = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	case 0xC: {
		spdm_algorithms_response_t spdm_response;

		zero_mem(&spdm_response, sizeof(spdm_response));
		spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_10;
		spdm_response.header.request_response_code = SPDM_ALGORITHMS;
		spdm_response.header.param1 = 0;
		spdm_response.header.param2 = 0;
		spdm_response.length = sizeof(spdm_algorithms_response_t);
		spdm_response.measurement_specification_sel =
			SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
		spdm_response.measurement_hash_algo =
			m_use_measurement_hash_algo;
		spdm_response.base_asym_sel = m_use_asym_algo;
		spdm_response.base_hash_sel = 0;
		spdm_response.ext_asym_sel_count = 0;
		spdm_response.ext_hash_sel_count = 0;

		spdm_transport_test_encode_message(spdm_context, NULL, FALSE,
						   FALSE, sizeof(spdm_response),
						   &spdm_response,
						   response_size, response);
	}
		return RETURN_SUCCESS;

	default:
		return RETURN_DEVICE_ERROR;
	}
}

void test_spdm_requester_negotiate_algorithms_case1(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x1;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

void test_spdm_requester_negotiate_algorithms_case2(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x2;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size,
			 sizeof(spdm_negotiate_algorithms_request_t) +
				 sizeof(spdm_algorithms_response_t));
}

void test_spdm_requester_negotiate_algorithms_case3(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x3;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_UNSUPPORTED);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

void test_spdm_requester_negotiate_algorithms_case4(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x4;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

void test_spdm_requester_negotiate_algorithms_case5(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x5;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_NO_RESPONSE);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

void test_spdm_requester_negotiate_algorithms_case6(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x6;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_SUCCESS);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size,
			 sizeof(spdm_negotiate_algorithms_request_t) +
				 sizeof(spdm_algorithms_response_t));
}

void test_spdm_requester_negotiate_algorithms_case7(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x7;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	assert_int_equal(spdm_context->connection_info.connection_state,
			 SPDM_CONNECTION_STATE_NOT_STARTED);
	assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);
}

void test_spdm_requester_negotiate_algorithms_case8(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x8;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
}

void test_spdm_requester_negotiate_algorithms_case9(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0x9;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_DEVICE_ERROR);
	//  assert_int_equal (spdm_context->transcript.message_a.buffer_size, sizeof(spdm_negotiate_algorithms_request_t) + sizeof(spdm_algorithms_response_t));
}

void test_spdm_requester_negotiate_algorithms_case10(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xA;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
	spdm_context->connection_info.algorithm.base_asym_algo = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(
		spdm_context->connection_info.algorithm.measurement_hash_algo,
		0);
}

void test_spdm_requester_negotiate_algorithms_case11(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xB;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
	spdm_context->connection_info.algorithm.base_asym_algo = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo = 0;
	spdm_context->connection_info.capability.flags |=
		SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
	spdm_context->local_context.capability.flags |=
		SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->connection_info.algorithm.base_asym_algo,
			 0);
}

void test_spdm_requester_negotiate_algorithms_case12(void **state)
{
	return_status status;
	spdm_test_context_t *spdm_test_context;
	spdm_context_t *spdm_context;

	spdm_test_context = *state;
	spdm_context = spdm_test_context->spdm_context;
	spdm_test_context->case_id = 0xC;
	spdm_context->connection_info.connection_state =
		SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_context->local_context.algorithm.measurement_hash_algo =
		m_use_measurement_hash_algo;
	spdm_context->local_context.algorithm.base_asym_algo = m_use_asym_algo;
	spdm_context->local_context.algorithm.bash_hash_algo = m_use_hash_algo;
	spdm_context->connection_info.algorithm.measurement_hash_algo = 0;
	spdm_context->connection_info.algorithm.base_asym_algo = 0;
	spdm_context->connection_info.algorithm.bash_hash_algo = 0;
	spdm_context->transcript.message_a.buffer_size = 0;

	status = spdm_negotiate_algorithms(spdm_context);
	assert_int_equal(status, RETURN_SECURITY_VIOLATION);
	assert_int_equal(spdm_context->connection_info.algorithm.bash_hash_algo,
			 0);
}

spdm_test_context_t m_spdm_requester_negotiate_algorithms_test_context = {
	SPDM_TEST_CONTEXT_SIGNATURE,
	TRUE,
	spdm_requester_negotiate_algorithms_test_send_message,
	spdm_requester_negotiate_algorithm_test_receive_message,
};

int spdm_requester_negotiate_algorithms_test_main(void)
{
	const struct CMUnitTest spdm_requester_negotiate_algorithms_tests[] = {
		// SendRequest failed
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case1),
		// Successful response
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case2),
		// connection_state check failed
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case3),
		// Error response: SPDM_ERROR_CODE_INVALID_REQUEST
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case4),
		// Always SPDM_ERROR_CODE_BUSY
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case5),
		// SPDM_ERROR_CODE_BUSY + Successful response
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case6),
		// Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case7),
		// Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case8),
		// SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case9),
		// When spdm_response.measurement_hash_algo is 0
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case10),
		// When spdm_response.base_asym_sel is 0
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case11),
		// When spdm_response.base_hash_sel is 0
		cmocka_unit_test(
			test_spdm_requester_negotiate_algorithms_case12),
	};

	setup_spdm_test_context(
		&m_spdm_requester_negotiate_algorithms_test_context);

	return cmocka_run_group_tests(spdm_requester_negotiate_algorithms_tests,
				      spdm_unit_test_group_setup,
				      spdm_unit_test_group_teardown);
}
