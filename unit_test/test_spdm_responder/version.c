/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#define LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT SPDM_MAX_VERSION_COUNT

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} libspdm_version_response_mine_t;
#pragma pack()

spdm_get_version_request_t m_libspdm_get_version_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_VERSION,
    },
};
size_t m_libspdm_get_version_request1_size = sizeof(m_libspdm_get_version_request1);

spdm_get_version_request_t m_libspdm_get_version_request3 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_VERSION,
    },
};
size_t m_libspdm_get_version_request3_size = sizeof(m_libspdm_get_version_request3);

spdm_get_version_request_t m_libspdm_get_version_request4 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_VERSION,
    },
};
size_t m_libspdm_get_version_request4_size = sizeof(m_libspdm_get_version_request4);

/**
 * Test 1: receiving a correct GET_VERSION from the requester.
 * Expected behavior: the responder accepts the request, produces a valid VERSION
 * response message, and then resets the connection state.
 **/
static void rsp_version_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);
}

/**
 * Test 2: receiving a GET_VERSION request that is smaller than the minimum allowed size.
 * Expected behavior: the responder refuses the GET_VERSION message and produces an ERROR
 * message indicating the InvalidRequest.
 **/
static void rsp_version_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          sizeof(spdm_get_version_request_t) - 1,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 3: receiving a correct GET_VERSION from the requester, but the responder is in
 * a Busy state.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the Buse state.
 **/
static void rsp_version_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
}

/**
 * Test 4: receiving a correct GET_VERSION from the requester, but the responder requires
 * resynchronization with the requester.
 * Expected behavior: the requester resets the communication upon receiving the GET_VERSION
 * message, fulfilling the resynchronization. A valid VERSION message is produced.
 **/
static void rsp_version_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
}

/**
 * Test 5: transcript message A cannot fit the incoming GET_VERSION request.
 * Expected behavior: the responder returns an ERROR message with code Unspecified and does
 * not retain transcript data.
 **/
static void rsp_version_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    size_t max_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    max_buffer_size = spdm_context->transcript.message_a.max_buffer_size;
    spdm_context->transcript.message_a.max_buffer_size =
        sizeof(spdm_get_version_request_t) - 1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);

    spdm_context->transcript.message_a.max_buffer_size = max_buffer_size;
}

/**
 * Test 6: receiving a GET_VERSION message in SPDM version 1.1 (in the header), but correct
 * 1.0-version format.
 * Expected behavior: the responder refuses the GET_VERSION message, produces an
 * ERROR message indicating the VersionMismatch, and will not reset the connection state.
 **/
static void rsp_version_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request3_size,
                                          &m_libspdm_get_version_request3,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_10);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AUTHENTICATED);
}

/**
 * Test 7: receiving a GET_VERSION request while the responder still has a valid session ID
 * from a previous exchange (i.e. GET_VERSION is received unexpectedly mid-session).
 * Expected behavior: the responder refuses the GET_VERSION message and produces an ERROR
 * message indicating the UnexpectedRequest.
 **/
static void rsp_version_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = 0xFFFFFFFF;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AUTHENTICATED);

    /* restore shared context state so that subsequent tests in this group are unaffected */
    spdm_context->last_spdm_request_session_id_valid = false;
}

/**
 * Test 8: receiving a correct GET_VERSION from the requester. Buffers A, B and C
 * already have arbitrary data.
 * Expected behavior: the responder accepts the request and produces a valid VERSION
 * response message, buffers A, B and C should be first reset, and then buffer A
 * receives only the exchanged GET_VERSION and VERSION messages.
 **/
static void rsp_version_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    /*filling buffers with arbitrary data*/
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, 10, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = 10;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_set_mem(spdm_context->transcript.message_b.buffer, 8, (uint8_t) 0xEE);
    spdm_context->transcript.message_b.buffer_size = 8;
    libspdm_set_mem(spdm_context->transcript.message_c.buffer, 12, (uint8_t) 0xDD);
    spdm_context->transcript.message_c.buffer_size = 12;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_version(
        spdm_context, m_libspdm_get_version_request1_size, &m_libspdm_get_version_request1,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT * sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     m_libspdm_get_version_request1_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer,
                        &m_libspdm_get_version_request1, m_libspdm_get_version_request1_size);
    assert_memory_equal(
        spdm_context->transcript.message_a.buffer + m_libspdm_get_version_request1_size,
        response, response_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
}

/**
 * Test 9: transcript message A can fit GET_VERSION but not the VERSION response.
 * Expected behavior: the responder returns an ERROR message with code Unspecified and
 * resets transcript message A.
 **/
static void rsp_version_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t *spdm_response;
    size_t max_buffer_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    max_buffer_size = spdm_context->transcript.message_a.max_buffer_size;
    spdm_context->transcript.message_a.max_buffer_size =
        sizeof(spdm_get_version_request_t);
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->transcript.message_a.buffer_size, 0);

    spdm_context->transcript.message_a.max_buffer_size = max_buffer_size;
}

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
/**
 * Test 10: receiving a correct GET_VERSION from the requester while encapsulated flows are in
 * progress both outside of a session and within a session, each of them interrupted by an
 * encapsulated ERROR(ResponseNotReady) that the responder has yet to follow up on.
 * Expected behavior: the responder produces a valid VERSION response and restarts negotiation
 * from AFTER_VERSION, and the GET_VERSION ends every encapsulated flow and discards every pending
 * ResponseNotReady, so that no flow of the previous connection can be resumed in the new one.
 **/
static void rsp_version_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_version_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    /* A general flow outside of a session, interrupted by ResponseNotReady. */
    spdm_context->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_GENERAL;
    spdm_context->encap_context.request_id = 2;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    spdm_context->encap_context.response_not_ready = true;
    spdm_context->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_GENERAL;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    /* A session-based mutual authentication flow within a session, likewise interrupted. */
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, 0xFFFFFFFF,
                              SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    session_info->encap_context.flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
    session_info->encap_context.request_id = 1;
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    session_info->encap_context.response_not_ready = true;
    session_info->encap_context.response_not_ready_flow_type = LIBSPDM_ENCAP_FLOW_SESS_MUT_AUTH;
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    response_size = sizeof(response);
    status = libspdm_get_response_version(spdm_context,
                                          m_libspdm_get_version_request1_size,
                                          &m_libspdm_get_version_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_version_response_t) +
                     LIBSPDM_DEFAULT_SPDM_VERSION_ENTRY_COUNT *
                     sizeof(spdm_version_number_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_VERSION);

    /* Version negotiation restarts from the beginning. */
    assert_int_equal(spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NORMAL);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_AFTER_VERSION);

    /* No flow survives GET_VERSION, and no interrupted flow can be resumed after it. */
    assert_int_equal(spdm_context->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
    assert_int_equal(session_info->encap_context.flow_type, LIBSPDM_ENCAP_FLOW_NONE);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    assert_false(spdm_context->encap_context.response_not_ready);
    assert_false(session_info->encap_context.response_not_ready);
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
    /* The session that the flow belonged to is gone as well. */
    assert_int_equal(session_info->session_id, INVALID_SESSION_ID);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

/* Teardown callbacks must observe the original ID and the new state before reuse. */
static uint32_t m_teardown_ids[LIBSPDM_MAX_SESSION_COUNT];
static size_t m_teardown_count;

static void libspdm_test_version_teardown_callback(
    void *context, uint32_t session_id, libspdm_session_state_t state)
{
    libspdm_session_info_t *session_info;
    size_t index;

    assert_int_equal(state, LIBSPDM_SESSION_STATE_NOT_STARTED);
    session_info = libspdm_get_session_info_via_session_id(context, session_id);
    assert_non_null(session_info);
    assert_int_equal(libspdm_secured_message_get_session_state(
                         session_info->secured_message_context), state);
    assert_true(m_teardown_count < LIBSPDM_MAX_SESSION_COUNT);
    for (index = 0; index < m_teardown_count; index++) {
        assert_int_not_equal(m_teardown_ids[index], session_id);
    }
    m_teardown_ids[m_teardown_count++] = session_id;
}

/* Exercise both reset entry points, including mixed states and unused slots. */
static void rsp_version_session_teardown(void **state)
{
    libspdm_test_context_t *test_context;
    libspdm_context_t *context;
    libspdm_session_info_t *session_info;
    spdm_get_version_request_t request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    size_t index;
    size_t count;
    size_t mode;
    libspdm_return_t status;

    test_context = *state;
    context = test_context->spdm_context;
    libspdm_reset_context(context);
    libspdm_register_session_state_callback_func(context,
                                                 libspdm_test_version_teardown_callback);
    count = LIBSPDM_MAX_SESSION_COUNT > 2 ? 2 : 1;
    for (mode = 0; mode < 2; mode++) {
        m_teardown_count = 0;
        for (index = 0; index < count; index++) {
            session_info = libspdm_assign_session_id(context, (uint32_t)(0x12340001 + index),
                                                     SECURED_SPDM_VERSION_11 <<
                                                     SPDM_VERSION_NUMBER_SHIFT_BIT,
                                                     index != 0);
            assert_non_null(session_info);
            libspdm_secured_message_set_session_state(
                session_info->secured_message_context,
                index == 0 ? LIBSPDM_SESSION_STATE_ESTABLISHED :
                LIBSPDM_SESSION_STATE_HANDSHAKING);
        }
        libspdm_zero_mem(&request, sizeof(request));
        request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
        request.header.request_response_code = SPDM_GET_VERSION;
        if (mode == 0) {
            /* A malformed request must leave active sessions untouched. */
            response_size = sizeof(response);
            status = libspdm_get_response_version(context, sizeof(request) - 1,
                                                  &request, &response_size, response);
            assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
            assert_int_equal(((spdm_message_header_t *)response)->request_response_code,
                             SPDM_ERROR);
            assert_int_equal(m_teardown_count, 0);
            response_size = sizeof(response);
            status = libspdm_get_response_version(context, sizeof(request),
                                                  &request, &response_size, response);
            assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
            assert_int_equal(((spdm_message_header_t *)response)->request_response_code,
                             SPDM_VERSION);
        } else {
            libspdm_reset_context(context);
        }
        assert_int_equal(m_teardown_count, count);
        for (index = 0; index < count; index++) {
            assert_int_equal(m_teardown_ids[index], 0x12340001 + index);
            assert_null(libspdm_get_session_info_via_session_id(
                            context, (uint32_t)(0x12340001 + index)));
        }
        assert_int_equal(context->current_dhe_session_count, 0);
        assert_int_equal(context->current_psk_session_count, 0);
        assert_int_equal(context->latest_session_id, INVALID_SESSION_ID);
        libspdm_reset_context(context);
        response_size = sizeof(response);
        assert_int_equal(libspdm_get_response_version(context, sizeof(request),
                                                      &request, &response_size, response),
                         LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(m_teardown_count, count);
    }
    libspdm_register_session_state_callback_func(context, NULL);
}

/* Free and terminate notify once; unused and already-not-started slots do not. */
static void rsp_version_free_session_teardown(void **state)
{
    libspdm_test_context_t *test_context;
    libspdm_context_t *context;
    libspdm_session_info_t *session_info;
    size_t mode;
    uint32_t session_id;

    test_context = *state;
    context = test_context->spdm_context;
    libspdm_reset_context(context);
    libspdm_register_session_state_callback_func(context,
                                                 libspdm_test_version_teardown_callback);
    for (mode = 0; mode < 5; mode++) {
        m_teardown_count = 0;
        session_id = (uint32_t)(0x43210001 + mode);
        session_info = libspdm_assign_session_id(context, session_id,
                                                 SECURED_SPDM_VERSION_11 <<
                                                 SPDM_VERSION_NUMBER_SHIFT_BIT, mode % 2 != 0);
        assert_non_null(session_info);
        if (mode != 4) {
            libspdm_secured_message_set_session_state(
                session_info->secured_message_context,
                mode % 2 == 0 ? LIBSPDM_SESSION_STATE_HANDSHAKING :
                LIBSPDM_SESSION_STATE_ESTABLISHED);
        }
        if (mode < 2 || mode == 4) {
            libspdm_free_session_id(context, session_id);
        } else {
            assert_int_equal(libspdm_terminate_session(context, session_id),
                             LIBSPDM_STATUS_SUCCESS);
        }
        assert_int_equal(m_teardown_count, mode == 4 ? 0 : 1);
        if (mode != 4) {
            assert_int_equal(m_teardown_ids[0], session_id);
        }
        assert_null(libspdm_get_session_info_via_session_id(context, session_id));
        assert_int_equal(context->current_dhe_session_count, 0);
        assert_int_equal(context->current_psk_session_count, 0);
        assert_int_equal(libspdm_terminate_session(context, session_id),
                         LIBSPDM_STATUS_INVALID_PARAMETER);
        assert_int_equal(m_teardown_count, mode == 4 ? 0 : 1);
    }
#if LIBSPDM_MAX_SESSION_COUNT > 1
    m_teardown_count = 0;
    session_info = libspdm_assign_session_id(context, 0x43210010,
                                             SECURED_SPDM_VERSION_11 <<
                                             SPDM_VERSION_NUMBER_SHIFT_BIT, true);
    assert_non_null(session_info);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info = libspdm_assign_session_id(context, 0x43210011,
                                             SECURED_SPDM_VERSION_11 <<
                                             SPDM_VERSION_NUMBER_SHIFT_BIT, false);
    assert_non_null(session_info);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_free_session_id(context, 0x43210010);
    assert_int_equal(m_teardown_count, 1);
    assert_int_equal(m_teardown_ids[0], 0x43210010);
    assert_int_equal(context->current_psk_session_count, 0);
    assert_int_equal(context->current_dhe_session_count, 1);
    assert_int_equal(libspdm_secured_message_get_session_state(session_info->secured_message_context),
                     LIBSPDM_SESSION_STATE_ESTABLISHED);
    assert_int_equal(context->latest_session_id, 0x43210011);
#endif
    libspdm_register_session_state_callback_func(context, NULL);
    libspdm_reset_context(context);
}

int libspdm_rsp_version_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_version_case1),
        cmocka_unit_test(rsp_version_session_teardown),
        cmocka_unit_test(rsp_version_free_session_teardown),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(rsp_version_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(rsp_version_case4),
        /* transcript.message_a cannot fit GET_VERSION */
        cmocka_unit_test(rsp_version_case5),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case6),
        /* Invalid request*/
        cmocka_unit_test(rsp_version_case7),
        /* Buffer verification*/
        cmocka_unit_test(rsp_version_case8),
        /* transcript.message_a cannot fit VERSION */
        cmocka_unit_test(rsp_version_case9),
#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        /* GET_VERSION ends every encapsulated flow and restarts version negotiation */
        cmocka_unit_test(rsp_version_case10),
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
