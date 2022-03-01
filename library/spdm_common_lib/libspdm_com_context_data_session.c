/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

/**
 * This function initializes the session info.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 **/
void libspdm_session_info_init(libspdm_context_t *spdm_context,
                               libspdm_session_info_t *session_info,
                               uint32_t session_id, bool use_psk)
{
    libspdm_session_type_t session_type;
    uint32_t capabilities_flag;

    capabilities_flag = spdm_context->connection_info.capability.flags &
                        spdm_context->local_context.capability.flags;
    switch (capabilities_flag &
            (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP)) {
    case 0:
        session_type = LIBSPDM_SESSION_TYPE_NONE;
        break;
    case (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP):
        session_type = LIBSPDM_SESSION_TYPE_ENC_MAC;
        break;
    case SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP:
        session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
        break;
    default:
        LIBSPDM_ASSERT(false);
        session_type = LIBSPDM_SESSION_TYPE_MAX;
        break;
    }

    zero_mem(session_info,
             OFFSET_OF(libspdm_session_info_t, secured_message_context));
    libspdm_secured_message_init_context(
        session_info->secured_message_context);
    session_info->session_id = session_id;
    session_info->use_psk = use_psk;
    libspdm_secured_message_set_use_psk(session_info->secured_message_context,
                                        use_psk);
    libspdm_secured_message_set_session_type(
        session_info->secured_message_context, session_type);
    libspdm_secured_message_set_algorithms(
        session_info->secured_message_context,
        spdm_context->connection_info.version,
        spdm_context->connection_info.secured_message_version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.dhe_named_group,
        spdm_context->connection_info.algorithm.aead_cipher_suite,
        spdm_context->connection_info.algorithm.key_schedule);
    libspdm_secured_message_set_psk_hint(
        session_info->secured_message_context,
        spdm_context->local_context.psk_hint,
        spdm_context->local_context.psk_hint_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_k.max_buffer_size =
        sizeof(session_info->session_transcript.message_k.buffer);
    session_info->session_transcript.message_f.max_buffer_size =
        sizeof(session_info->session_transcript.message_f.buffer);
    session_info->session_transcript.message_m.max_buffer_size =
        sizeof(session_info->session_transcript.message_m.buffer);
#else
    session_info->session_transcript.temp_message_k.max_buffer_size =
        sizeof(session_info->session_transcript.temp_message_k.buffer);
#endif
}

/**
 * This function gets the session info via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info.
 **/
void *libspdm_get_session_info_via_session_id(const void *context,
                                              uint32_t session_id)
{
    const libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uintn index;

    if (session_id == INVALID_SESSION_ID) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "libspdm_get_session_info_via_session_id - Invalid session_id\n"));
        LIBSPDM_ASSERT(false);
        return NULL;
    }

    spdm_context = context;

    session_info = (libspdm_session_info_t *)spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if (session_info[index].session_id == session_id) {
            return &session_info[index];
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                   "libspdm_get_session_info_via_session_id - not found session_id\n"));
    return NULL;
}

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return secured message context.
 **/
void *libspdm_get_secured_message_context_via_session_id(const void *spdm_context,
                                                         uint32_t session_id)
{
    libspdm_session_info_t *session_info;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return NULL;
    } else {
        return session_info->secured_message_context;
    }
}

/**
 * This function gets the secured message context via session ID.
 *
 * @param  spdm_session_info              A pointer to the SPDM context.
 *
 * @return secured message context.
 **/
void *
libspdm_get_secured_message_context_via_session_info(void *spdm_session_info)
{
    libspdm_session_info_t *session_info;

    session_info = spdm_session_info;
    if (session_info == NULL) {
        return NULL;
    } else {
        return session_info->secured_message_context;
    }
}

/**
 * This function assigns a new session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 *
 * @return session info associated with this new session ID.
 **/
void *libspdm_assign_session_id(void *context, uint32_t session_id,
                                bool use_psk)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uintn index;

    spdm_context = context;

    if (session_id == INVALID_SESSION_ID) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "libspdm_assign_session_id - Invalid session_id\n"));
        LIBSPDM_ASSERT(false);
        return NULL;
    }

    session_info = spdm_context->session_info;

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if (session_info[index].session_id == session_id) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_assign_session_id - Duplicated session_id\n"));
            LIBSPDM_ASSERT(false);
            return NULL;
        }
    }

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if (session_info[index].session_id == INVALID_SESSION_ID) {
            libspdm_session_info_init(spdm_context,
                                      &session_info[index], session_id,
                                      use_psk);
            spdm_context->latest_session_id = session_id;
            return &session_info[index];
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_assign_session_id - MAX session_id\n"));
    return NULL;
}

/**
 * This function allocates half of session ID for a requester.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return half of session ID for a requester.
 **/
uint16_t libspdm_allocate_req_session_id(libspdm_context_t *spdm_context)
{
    uint16_t req_session_id;
    libspdm_session_info_t *session_info;
    uintn index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF0000) ==
            (INVALID_SESSION_ID & 0xFFFF0000)) {
            req_session_id = (uint16_t)(0xFFFF - index);
            return req_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_req_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}

/**
 * This function allocates half of session ID for a responder.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 *
 * @return half of session ID for a responder.
 **/
uint16_t libspdm_allocate_rsp_session_id(const libspdm_context_t *spdm_context)
{
    uint16_t rsp_session_id;
    const libspdm_session_info_t *session_info;
    uintn index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if ((session_info[index].session_id & 0xFFFF) ==
            (INVALID_SESSION_ID & 0xFFFF)) {
            rsp_session_id = (uint16_t)(0xFFFF - index);
            return rsp_session_id;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_allocate_rsp_session_id - MAX session_id\n"));
    return (INVALID_SESSION_ID & 0xFFFF);
}

/**
 * This function frees a session ID.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The SPDM session ID.
 **/
void libspdm_free_session_id(void *context, uint32_t session_id)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uintn index;

    spdm_context = context;

    if (session_id == INVALID_SESSION_ID) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "libspdm_free_session_id - Invalid session_id\n"));
        LIBSPDM_ASSERT(false);
        return;
    }

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if (session_info[index].session_id == session_id) {
            libspdm_session_info_init(spdm_context,
                                      &session_info[index],
                                      INVALID_SESSION_ID, false);
            return;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_free_session_id - MAX session_id\n"));
    LIBSPDM_ASSERT(false);
    return;
}
