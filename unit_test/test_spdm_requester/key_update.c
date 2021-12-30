/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

static uint8_t my_last_token;
static uint8_t my_last_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t my_last_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
static uint64_t my_last_rsp_sequence_number;

static void spdm_set_standard_key_update_test_state(
    IN OUT spdm_context_t *spdm_context, IN OUT uint32_t *session_id)
{
    void                   *data;
    uintn                  data_size;
    void                   *hash;
    uintn                  hash_size;
    spdm_session_info_t    *session_info;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    read_responder_public_certificate_chain(m_use_hash_algo,
                        m_use_asym_algo, &data,
                        &data_size, &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_use_aead_algo;
    spdm_context->connection_info.peer_used_cert_chain_buffer_size =
        data_size;
    copy_mem(spdm_context->connection_info.peer_used_cert_chain_buffer,
          data, data_size);

    *session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    spdm_session_info_init(spdm_context, session_info, *session_id, TRUE);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    free(data);
}

static void spdm_set_standard_key_update_test_secrets(
    IN OUT spdm_secured_message_context_t *secured_message_context,
    OUT uint8_t *m_rsp_secret_buffer, IN uint8_t rsp_secret_fill,
    OUT uint8_t *m_req_secret_buffer, IN uint8_t req_secret_fill)
{
    set_mem(m_rsp_secret_buffer, secured_message_context
        ->hash_size, rsp_secret_fill);
    set_mem(m_req_secret_buffer, secured_message_context
              ->hash_size, req_secret_fill);

    copy_mem(secured_message_context->application_secret
             .response_data_secret,
          m_rsp_secret_buffer, secured_message_context->aead_key_size);
    copy_mem(secured_message_context->application_secret
             .request_data_secret,
          m_req_secret_buffer, secured_message_context->aead_key_size);

    set_mem(secured_message_context->application_secret
             .response_data_encryption_key,
          secured_message_context->aead_key_size, (uint8_t)(0xFF));
    set_mem(secured_message_context->application_secret
             .response_data_salt,
          secured_message_context->aead_iv_size, (uint8_t)(0xFF));


    set_mem(secured_message_context->application_secret
             .request_data_encryption_key,
          secured_message_context->aead_key_size, (uint8_t)(0xEE));
    set_mem(secured_message_context->application_secret
             .request_data_salt,
          secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.
          response_data_sequence_number = 0;
    secured_message_context->application_secret.
          request_data_sequence_number = 0;
}

static void spdm_compute_secret_update(uintn hash_size,
    IN const uint8_t *in_secret, OUT uint8_t *out_secret,
    IN uintn out_secret_size)
{
    uint8_t    m_bin_str9[128];
    uintn    m_bin_str9_size;
    uint16_t   length;

    length = (uint16_t) hash_size;
    copy_mem(m_bin_str9, &length, sizeof(uint16_t));
    copy_mem(m_bin_str9 + sizeof(uint16_t), SPDM_BIN_CONCAT_LABEL,
          sizeof(SPDM_BIN_CONCAT_LABEL) - 1);
    copy_mem(m_bin_str9 + sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1,
          SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL));
    m_bin_str9_size = sizeof(uint16_t) + sizeof(SPDM_BIN_CONCAT_LABEL) - 1 +
          sizeof(SPDM_BIN_STR_9_LABEL) - 1;
    /*context is NULL for key update*/

    libspdm_hkdf_expand(m_use_hash_algo, in_secret, hash_size, m_bin_str9,
          m_bin_str9_size, out_secret, out_secret_size);
}

return_status spdm_requester_key_update_test_send_message(
    IN void *spdm_context, IN uintn request_size, IN void *request,
    IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;
    case 0x2: {
        return_status       status;
        uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn               decoded_message_size;
        uint32_t              session_id;
        uint32_t              *message_session_id;
        boolean             is_app_message;
        spdm_session_info_t *session_info;

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;
        decoded_message_size = sizeof(decoded_message);

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
        status = spdm_transport_test_decode_message(spdm_context,
              &message_session_id, &is_app_message, TRUE, request_size,
              request, &decoded_message_size, decoded_message);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }

        my_last_token = ((spdm_key_update_request_t
              *) decoded_message)->header.param2;
    }
        return RETURN_SUCCESS;
    case 0x3: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x4: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x5: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x6: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x7:
    case 0x8:
        return RETURN_SUCCESS;
    case 0x9: {
        static uintn sub_index = 0;

        if(sub_index != 1) {
            return_status          status;
            uint8_t decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn decoded_message_size;
            uint32_t                 session_id;
            uint32_t *message_session_id;
            boolean is_app_message;
            spdm_session_info_t    *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0xA:
        return RETURN_SUCCESS;
    case 0xB:
    case 0xC:
    case 0xD:
    case 0xE:
    case 0xF:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15: {
        return_status       status;
        uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn               decoded_message_size;
        uint32_t              session_id;
        uint32_t              *message_session_id;
        boolean             is_app_message;
        spdm_session_info_t *session_info;

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;
        decoded_message_size = sizeof(decoded_message);

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
        status = spdm_transport_test_decode_message(spdm_context,
              &message_session_id, &is_app_message, TRUE, request_size,
              request, &decoded_message_size, decoded_message);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }

        my_last_token = ((spdm_key_update_request_t
              *) decoded_message)->header.param2;
    }
        return RETURN_SUCCESS;
    case 0x16: {
        static uintn sub_index = 0;

        if(sub_index < 2) {
            return_status          status;
            uint8_t decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn decoded_message_size;
            uint32_t                 session_id;
            uint32_t *message_session_id;
            boolean is_app_message;
            spdm_session_info_t    *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x17: {
        static uintn sub_index = 0;

        DEBUG((DEBUG_INFO, "send message: %d\n", sub_index));

        if(sub_index%2 == 0) {
            return_status          status;
            uint8_t decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn decoded_message_size;
            uint32_t                 session_id;
            uint32_t *message_session_id;
            boolean is_app_message;
            spdm_session_info_t    *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;

            DEBUG((DEBUG_INFO, "last token: %x\n", my_last_token));
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x18:
    case 0x19:
    case 0x1A: {
        return_status       status;
        uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn               decoded_message_size;
        uint32_t              session_id;
        uint32_t              *message_session_id;
        boolean             is_app_message;
        spdm_session_info_t *session_info;

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;
        decoded_message_size = sizeof(decoded_message);

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
        status = spdm_transport_test_decode_message(spdm_context,
              &message_session_id, &is_app_message, TRUE, request_size,
              request, &decoded_message_size, decoded_message);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }

        my_last_token = ((spdm_key_update_request_t
              *) decoded_message)->header.param2;
    }
        return RETURN_SUCCESS;
    case 0x1B: {
        return_status       status;
        uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
        uintn               decoded_message_size;
        uint32_t              session_id;
        uint32_t              *message_session_id;
        boolean             is_app_message;
        spdm_session_info_t *session_info;

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;
        decoded_message_size = sizeof(decoded_message);

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
        status = spdm_transport_test_decode_message(spdm_context,
              &message_session_id, &is_app_message, TRUE, request_size,
              request, &decoded_message_size, decoded_message);
        if (RETURN_ERROR(status)) {
            return RETURN_DEVICE_ERROR;
        }

        my_last_token = ((spdm_key_update_request_t
              *) decoded_message)->header.param2;
    }
        return RETURN_SUCCESS;
    case 0x1C: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x1D: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x1E: {
        static uintn sub_index = 0;

        if(sub_index > 0) {
            return_status       status;
            uint8_t               decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn               decoded_message_size;
            uint32_t              session_id;
            uint32_t              *message_session_id;
            boolean             is_app_message;
            spdm_session_info_t *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x1F:
    case 0x20:
        return RETURN_SUCCESS;
    case 0x21: {
        static uintn sub_index = 0;

        if(sub_index != 1) {
            return_status          status;
            uint8_t decoded_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
            uintn decoded_message_size;
            uint32_t                 session_id;
            uint32_t *message_session_id;
            boolean is_app_message;
            spdm_session_info_t    *session_info;

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;
            decoded_message_size = sizeof(decoded_message);

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return RETURN_DEVICE_ERROR;
            }

            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.request_data_sequence_number--;
            status = spdm_transport_test_decode_message(spdm_context,
                  &message_session_id, &is_app_message, TRUE, request_size,
                  request, &decoded_message_size, decoded_message);
            if (RETURN_ERROR(status)) {
                return RETURN_DEVICE_ERROR;
            }

            my_last_token = ((spdm_key_update_request_t
                  *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;
    case 0x22:
        return RETURN_SUCCESS;
    default:
        return RETURN_DEVICE_ERROR;
    }
}

return_status spdm_requester_key_update_test_receive_message(
    IN void *spdm_context, IN OUT uintn *response_size,
    IN OUT void *response, IN uint64_t timeout)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = get_spdm_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return RETURN_DEVICE_ERROR;

    case 0x2: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x3: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x4: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
    }
        return RETURN_SUCCESS;

    case 0x5: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
    }
        return RETURN_SUCCESS;

    case 0x6: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_error_response_t spdm_response;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x7: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
    }
        return RETURN_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response.header.param2 = 0;
        spdm_response.extend_error_data.rd_exponent = 1;
        spdm_response.extend_error_data.rd_tm = 1;
        spdm_response.extend_error_data.request_code = SPDM_KEY_UPDATE;
        spdm_response.extend_error_data.token = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
    }
        return RETURN_SUCCESS;

    case 0x9: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_error_response_data_response_not_ready_t
                spdm_response;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code =
                SPDM_KEY_UPDATE;
            spdm_response.extend_error_data.token = 1;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0xA: {
        static uint16_t error_code = SPDM_ERROR_CODE_RESERVED_00;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_error_response_t    spdm_response;

        if(error_code <= 0xff) {
            zero_mem (&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = (uint8_t) error_code;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return RETURN_SUCCESS;

    case 0xB: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0xC: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        /*wrong response code*/
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0xD: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0xE: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0xF: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            /*wrong token*/
            spdm_response.header.param2 = my_last_token + 1;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x10: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            /*wrong operation code*/
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x11: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 1) {
            spdm_error_response_t  spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x12: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else {
            spdm_error_response_t  spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x13: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 1) {
            spdm_error_response_t spdm_response;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x14: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 1) {
            spdm_error_response_t  spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x15: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else {
            spdm_error_response_data_response_not_ready_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code = SPDM_KEY_UPDATE;
            spdm_response.extend_error_data.token = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x16: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 1) {
            spdm_error_response_data_response_not_ready_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code = SPDM_KEY_UPDATE;
            spdm_response.extend_error_data.token = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }
        else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            ((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x17: {
        static uintn sub_index = 0;
        static uint16_t error_code = SPDM_ERROR_CODE_RESERVED_00;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        if(error_code <= 0xff) {
            if (sub_index%2 == 0) {
                spdm_key_update_response_t spdm_response;

                spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
                spdm_response.header.request_response_code =
                      SPDM_KEY_UPDATE_ACK;
                spdm_response.header.param1 =
                      SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
                spdm_response.header.param2 = my_last_token;

                spdm_transport_test_encode_message(spdm_context,
                               &session_id, FALSE, FALSE,
                               sizeof(spdm_response), &spdm_response,
                               response_size, response);
                /* WALKAROUND: If just use single context to encode
                   message and then decode message */
                ((spdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->application_secret.response_data_sequence_number--;
            }
            else {
                spdm_error_response_t    spdm_response;

                zero_mem (&spdm_response, sizeof(spdm_response));
                spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
                spdm_response.header.request_response_code = SPDM_ERROR;
                spdm_response.header.param1 = (uint8_t) error_code;
                spdm_response.header.param2 = 0;

                spdm_transport_test_encode_message(spdm_context,
                               &session_id, FALSE, FALSE,
                               sizeof(spdm_response), &spdm_response,
                               response_size, response);
                /* WALKAROUND: If just use single context to encode
                   message and then decode message */
                ((spdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->application_secret.response_data_sequence_number--;

                error_code++;
                /*busy is treated in cases 5 and 6*/
                if(error_code == SPDM_ERROR_CODE_BUSY) {
                    error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
                }
                /*skip some reserved error codes (0d to 3e)*/
                if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
                    error_code = SPDM_ERROR_CODE_RESERVED_3F;
                }
                /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
                if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
                    error_code = SPDM_ERROR_CODE_RESERVED_FD;
                }
            }
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x18: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            /*wrong response code*/
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x19: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            /*wrong token*/
            spdm_response.header.param2 = my_last_token + 1;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x1A: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            /*wrong operation code*/
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response.header.param2 = my_last_token;
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x1B: {
        static uintn sub_index = 0;

        spdm_key_update_response_t spdm_response;
        uint32_t                     session_id;
        spdm_session_info_t        *session_info;

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response.header.param2 = my_last_token;
        } else if (sub_index == 1) {
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            /* as it is using single context, the keys were updated
               in the requester and do not need to be updated before
               sending the response */
        }

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
           message and then decode message */
        ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x1C: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        copy_mem(curr_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
        copy_mem(curr_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = my_last_rsp_sequence_number;

        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, my_last_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, my_last_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = my_last_rsp_sequence_number;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);

        /*restore new key*/
        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, curr_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, curr_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return RETURN_SUCCESS;

    case 0x1D: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        copy_mem(curr_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
        copy_mem(curr_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = my_last_rsp_sequence_number;

        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, my_last_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, my_last_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = my_last_rsp_sequence_number;

        /* once the sequence number is used, it should be increased for next BUSY nessage.*/
        my_last_rsp_sequence_number ++;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);

        /*restore new key*/
        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, curr_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, curr_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return RETURN_SUCCESS;

    case 0x1E: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        if (sub_index == 0) {
            spdm_error_response_t spdm_response;

            uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
            uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
            uint64_t curr_rsp_sequence_number;

            /*use previous key to send*/
            copy_mem(curr_rsp_enc_key, secured_message_context
                  ->application_secret.response_data_encryption_key,
                  secured_message_context->aead_key_size);
            copy_mem(curr_rsp_salt, secured_message_context
                  ->application_secret.response_data_salt,
                  secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = my_last_rsp_sequence_number;

            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, my_last_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, my_last_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = my_last_rsp_sequence_number;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);

            /*restore new key*/
            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, curr_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, curr_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = curr_rsp_sequence_number;
        } else if (sub_index == 1) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            secured_message_context->application_secret
                  .response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            secured_message_context->application_secret
                  .response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x1F: {
        spdm_error_response_t  spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        copy_mem(curr_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
        copy_mem(curr_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = my_last_rsp_sequence_number;

        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, my_last_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, my_last_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = my_last_rsp_sequence_number;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response.header.param2 = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);

        /*restore new key*/
        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, curr_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, curr_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return RETURN_SUCCESS;

    case 0x20: {
        spdm_error_response_data_response_not_ready_t spdm_response;
        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        copy_mem(curr_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
        copy_mem(curr_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = my_last_rsp_sequence_number;

        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, my_last_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, my_last_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = my_last_rsp_sequence_number;

        spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response.header.request_response_code = SPDM_ERROR;
        spdm_response.header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response.header.param2 = 0;
        spdm_response.extend_error_data.rd_exponent = 1;
        spdm_response.extend_error_data.rd_tm = 1;
        spdm_response.extend_error_data.request_code = SPDM_KEY_UPDATE;
        spdm_response.extend_error_data.token = 0;

        spdm_transport_test_encode_message(spdm_context, &session_id,
                           FALSE, FALSE, sizeof(spdm_response),
                           &spdm_response, response_size, response);

        /*restore new key*/
        copy_mem(secured_message_context->application_secret
              .response_data_encryption_key, curr_rsp_enc_key,
              secured_message_context->aead_key_size);
        copy_mem(secured_message_context->application_secret
              .response_data_salt, curr_rsp_salt,
              secured_message_context->aead_iv_size);
        secured_message_context->application_secret
              .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return RETURN_SUCCESS;

    case 0x21: {
        static uintn sub_index = 0;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_secured_message_context_t *secured_message_context;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        if (sub_index == 0) {
            spdm_error_response_data_response_not_ready_t
                spdm_response;

            uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
            uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
            uint64_t curr_rsp_sequence_number;

            /*use previous key to send*/
            copy_mem(curr_rsp_enc_key, secured_message_context
                  ->application_secret.response_data_encryption_key,
                  secured_message_context->aead_key_size);
            copy_mem(curr_rsp_salt, secured_message_context
                  ->application_secret.response_data_salt,
                  secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = my_last_rsp_sequence_number;

            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, my_last_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, my_last_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = my_last_rsp_sequence_number;

            spdm_response.header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response.header.param2 = 0;
            spdm_response.extend_error_data.rd_exponent = 1;
            spdm_response.extend_error_data.rd_tm = 1;
            spdm_response.extend_error_data.request_code =
                SPDM_KEY_UPDATE;
            spdm_response.extend_error_data.token = 1;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);

            /*restore new key*/
            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, curr_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, curr_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = curr_rsp_sequence_number;
        } else if (sub_index == 1) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
                  SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            secured_message_context->application_secret
                  .response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t spdm_response;

            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code =
              SPDM_KEY_UPDATE_ACK;
            spdm_response.header.param1 =
                  SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response.header.param2 = my_last_token;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);
            /* WALKAROUND: If just use single context to encode
               message and then decode message */
            secured_message_context->application_secret
                  .response_data_sequence_number--;
        }

        sub_index++;
    }
        return RETURN_SUCCESS;

    case 0x22: {
        static uint16_t error_code = SPDM_ERROR_CODE_RESERVED_00;

        uint32_t                 session_id;
        spdm_session_info_t    *session_info;

        spdm_error_response_t    spdm_response;

        spdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return RETURN_DEVICE_ERROR;
        }
        secured_message_context = session_info->secured_message_context;

        if(error_code <= 0xff) {
            /*use previous key to send*/
            copy_mem(curr_rsp_enc_key, secured_message_context
                  ->application_secret.response_data_encryption_key,
                  secured_message_context->aead_key_size);
            copy_mem(curr_rsp_salt, secured_message_context
                  ->application_secret.response_data_salt,
                  secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = my_last_rsp_sequence_number;

            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, my_last_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, my_last_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = my_last_rsp_sequence_number;

            zero_mem (&spdm_response, sizeof(spdm_response));
            spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response.header.request_response_code = SPDM_ERROR;
            spdm_response.header.param1 = (uint8_t) error_code;
            spdm_response.header.param2 = 0;

            spdm_transport_test_encode_message(spdm_context,
                           &session_id, FALSE, FALSE,
                           sizeof(spdm_response), &spdm_response,
                           response_size, response);

            /*restore new key*/
            copy_mem(secured_message_context->application_secret
                  .response_data_encryption_key, curr_rsp_enc_key,
                  secured_message_context->aead_key_size);
            copy_mem(secured_message_context->application_secret
                  .response_data_salt, curr_rsp_salt,
                  secured_message_context->aead_iv_size);
            secured_message_context->application_secret
                  .response_data_sequence_number = curr_rsp_sequence_number;
        }

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return RETURN_SUCCESS;

    default:
        return RETURN_DEVICE_ERROR;
    }
}


/**
  Test 1: when no KEY_UPDATE_ACK message is received, and the client
  returns a device error.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void test_spdm_requester_key_update_case1(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
}

/**
  Test 2: receiving a correct UPDATE_KEY_ACK message for updating
  only the request data key.
  Expected behavior: client returns a Status of RETURN_SUCCESS, the
  request data key is updated, but not the response data key.
**/
void test_spdm_requester_key_update_case2(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 3: requester state has not been negotiated, as if GET_VERSION,
  GET_CAPABILITIES and NEGOTIATE_ALGORITHMS had not been exchanged.
  Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
**/
void test_spdm_requester_key_update_case3(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    /*state not negotiated*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_UNSUPPORTED);
}

/**
  Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating InvalidParameters when updating key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case4(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the Busy status of the responder, when updating key.
  Expected behavior: client returns a Status of RETURN_NO_RESPONSE, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case5(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_NO_RESPONSE);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 6: the requester is setup correctly (see Test 2), but, when updating
  key, on the first try, receiving a Busy ERROR message, and on retry,
  receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY behavior is
  not altered.
  Expected behavior: client returns a Status of RETURN_SUCCESS, the
  request data key is updated, but not the response data key.
**/
void test_spdm_requester_key_update_case6(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the RequestResynch status of the responder, when updating
  key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
  communication is reset to expect a new GET_VERSION message.
**/
void test_spdm_requester_key_update_case7(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
             LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
  Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the ResponseNotReady status of the responder, when
  updating key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case8(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 9: the requester is setup correctly (see Test 2), but, when updating
  key, on the first try, receiving a ResponseNotReady ERROR message, and on
  retry, receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY
  behavior is not altered.
  Expected behavior: client returns a Status of RETURN_SUCCESS, the
  request data key is updated, but not the response data key.
**/
void test_spdm_requester_key_update_case9(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 10: receiving an unexpected ERROR message from the responder,
  when updating key.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case10(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;
    uint16_t                 error_code;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_set_standard_key_update_test_secrets(
              session_info->secured_message_context,
              m_rsp_secret_buffer, (uint8_t)(0xFF),
              m_req_secret_buffer, (uint8_t)(0xEE));

        /*no keys are updated*/

        status = libspdm_key_update(
            spdm_context, session_id, TRUE);

        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.request_data_secret,
              m_req_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.response_data_secret,
              m_rsp_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

void test_spdm_requester_key_update_case11(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
                    spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
                    spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
                    spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
                    spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
}

/**
  Test 12: requester is not setup correctly to support key update
  (no capabilities). The responder would attempt to return a correct
  KEY_UPDATE_ACK message.
  Expected behavior: client returns a Status of RETURN_UNSUPPORTED,
  and no keys are updated.
**/
void test_spdm_requester_key_update_case12(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    /*no capabilities*/
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_UNSUPPORTED);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 13: receiving an incorrect KEY_UPDATE_ACK message, with wrong
  response code, but all other field correct, when updating key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR,
  no keys are updated.
**/
void test_spdm_requester_key_update_case13(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 14: requester is not setup correctly by not initializing a
  session during KEY_EXCHANGE. The responder would attempt to
  return a correct KEY_UPDATE_ACK message.
  Expected behavior: client returns a Status of RETURN_UNSUPPORTED,
  and no keys are updated.
**/
void test_spdm_requester_key_update_case14(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    /*session not initialized*/
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_UNSUPPORTED);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 15: the requester is setup correctly (see Test 2), but receives a
  KEY_UPDATE_ACK response with the wrong token. The VERIFY_KEY behavior
  is not altered.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case15(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 16: the requester is setup correctly (see Test 2), but receives a
  KEY_UPDATE_ACK response with the operation code. The VERIFY_KEY
  behavior is not altered.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case16(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 17: the requester is setup correctly (see Test 2), but receives an
  ERROR message indicating InvalidParameters when verifying key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case17(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 18: the requester is setup correctly (see Test 2), but receives an
  ERROR message indicating the Busy status of the responder, when verifying
  key.
  Expected behavior: client returns a Status of RETURN_NO_RESPONSE, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case18(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_NO_RESPONSE);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 19: the requester is setup correctly (see Test 2), but, when
  verifying key, on the first try, receiving a Busy ERROR message,
  and on retry, receiving a correct KEY_UPDATE_ACK message. The
  VERIFY_KEY behavior is not altered.
  Expected behavior: client returns a Status of RETURN_SUCCESS, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case19(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 20: the requester is setup correctly (see Test 2), but receives an
  ERROR message indicating the RequestResynch status of the responder, when
  verifying key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
  communication is reset to expect a new GET_VERSION message.
**/
void test_spdm_requester_key_update_case20(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
             LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
  Test 21: the requester is setup correctly (see Test 2), but receives an
  ERROR message indicating the ResponseNotReady status of the responder, when
  verifying key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case21(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 22: the requester is setup correctly (see Test 2), but, when verifying
  key, on the first try, receiving a ResponseNotReady ERROR message, and on
  retry, receiving a correct KEY_UPDATE_ACK message.
  Expected behavior: client returns a Status of RETURN_SUCCESS, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case22(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 23: receiving an unexpected ERROR message from the responder,
  when verifying key.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case23(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;
    uint16_t                 error_code;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_set_standard_key_update_test_secrets(
              session_info->secured_message_context,
              m_rsp_secret_buffer, (uint8_t)(0xFF),
              m_req_secret_buffer, (uint8_t)(0xEE));

        /*request side updated*/
        spdm_compute_secret_update(((spdm_secured_message_context_t
                 *)(session_info->secured_message_context))->hash_size,
              m_req_secret_buffer, m_req_secret_buffer,
              sizeof(m_req_secret_buffer));
        /*response side *not* updated*/

        status = libspdm_key_update(
            spdm_context, session_id, TRUE);

        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.request_data_secret,
              m_req_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.response_data_secret,
              m_rsp_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

/**
  Test 24: receiving an incorrect KEY_UPDATE_ACK message, with wrong
  response code, but all other field correct, when verifying key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case24(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 25: the requester is setup correctly (see Test 2), and receives a
  correct KEY_UPDATE_ACK to update key. However, it receives a
  KEY_UPDATE_ACK response with the wrong token to verify the key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case25(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 26: the requester is setup correctly (see Test 2) and receives a
  correct KEY_UPDATE_ACK to update key. However, it receives a
  KEY_UPDATE_ACK response with the wrong operation code to verify the key.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
  request data key is not rollbacked.
**/
void test_spdm_requester_key_update_case26(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, TRUE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 27: receiving a correct UPDATE_KEY_ACK message for updating
  both the request data key and the response data key.
  Expected behavior: client returns a Status of RETURN_SUCCESS, and
  the request data key and response data key are updated.
**/
void test_spdm_requester_key_update_case27(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_rsp_secret_buffer, m_rsp_secret_buffer,
          sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 28: the requester is setup correctly (see Test 27), but receives an
  ERROR message indicating InvalidParameters when updating all keys.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case28(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 29: the requester is setup correctly (see Test 27), but receives an
  ERROR message indicating the Busy status of the responder, when updating
  all keys.
  Expected behavior: client returns a Status of RETURN_NO_RESPONSE, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case29(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_NO_RESPONSE);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 30: the requester is setup correctly (see Test 27), but, when updating
  all keys, on the first try, receiving a Busy ERROR message, and on retry,
  receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY behavior is
  not altered.
  Expected behavior: client returns a Status of RETURN_SUCCESS, and
  the request data key and response data key are updated.
**/
void test_spdm_requester_key_update_case30(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_rsp_secret_buffer, m_rsp_secret_buffer,
          sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 31: the requester is setup correctly (see Test 27), but receives an
  ERROR message indicating the RequestResynch status of the responder, when
  updating all keys.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
  communication is reset to expect a new GET_VERSION message.
**/
void test_spdm_requester_key_update_case31(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_int_equal(spdm_context->connection_info.connection_state,
             LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
  Test 32: the requester is setup correctly (see Test 27), but receives an
  ERROR message indicating the ResponseNotReady status of the responder, when
  updating all keys.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case32(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_DEVICE_ERROR);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 33: the requester is setup correctly (see Test 27), but, when updating
  all keys, on the first try, receiving a ResponseNotReady ERROR message, and
  on retry, receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY
  behavior is not altered.
  Expected behavior: client returns a Status of RETURN_SUCCESS, and
  the request data key and response data key are updated.
**/
void test_spdm_requester_key_update_case33(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;

    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    spdm_set_standard_key_update_test_secrets(
          session_info->secured_message_context,
          m_rsp_secret_buffer, (uint8_t)(0xFF),
          m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    copy_mem(my_last_rsp_enc_key, secured_message_context
              ->application_secret.response_data_encryption_key,
              secured_message_context->aead_key_size);
    copy_mem(my_last_rsp_salt, secured_message_context
              ->application_secret.response_data_salt,
              secured_message_context->aead_iv_size);
    my_last_rsp_sequence_number = secured_message_context
              ->application_secret.response_data_sequence_number;

    /*request side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_req_secret_buffer, m_req_secret_buffer,
          sizeof(m_req_secret_buffer));
    /*response side updated*/
    spdm_compute_secret_update(((spdm_secured_message_context_t
             *)(session_info->secured_message_context))->hash_size,
          m_rsp_secret_buffer, m_rsp_secret_buffer,
          sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(
        spdm_context, session_id, FALSE);

    assert_int_equal(status, RETURN_SUCCESS);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.request_data_secret,
          m_req_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((spdm_secured_message_context_t
              *)(session_info->secured_message_context))
              ->application_secret.response_data_secret,
          m_rsp_secret_buffer, ((spdm_secured_message_context_t
          *)(session_info->secured_message_context))->hash_size);
}

/**
  Test 34: receiving an unexpected ERROR message from the responder,
  when updating all keys.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and
  no keys should be updated.
**/
void test_spdm_requester_key_update_case34(void **state)
{
    return_status          status;
    spdm_test_context_t    *spdm_test_context;
    spdm_context_t         *spdm_context;
    uint32_t                 session_id;
    spdm_session_info_t    *session_info;
    uint16_t                 error_code;

    uint8_t    m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t    m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_set_standard_key_update_test_state(
          spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    error_code = SPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_set_standard_key_update_test_secrets(
              session_info->secured_message_context,
              m_rsp_secret_buffer, (uint8_t)(0xFF),
              m_req_secret_buffer, (uint8_t)(0xEE));

        /*store previous encryption state*/
        copy_mem(my_last_rsp_enc_key, secured_message_context
                  ->application_secret.response_data_encryption_key,
                  secured_message_context->aead_key_size);
        copy_mem(my_last_rsp_salt, secured_message_context
                  ->application_secret.response_data_salt,
                  secured_message_context->aead_iv_size);
        my_last_rsp_sequence_number = secured_message_context
                  ->application_secret.response_data_sequence_number;

        /*no keys are updated*/

        status = libspdm_key_update(
            spdm_context, session_id, FALSE);

        /* assert_int_equal (status, RETURN_DEVICE_ERROR);*/
        ASSERT_INT_EQUAL_CASE (status, RETURN_DEVICE_ERROR, error_code);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.request_data_secret,
              m_req_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((spdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                  ->application_secret.response_data_secret,
              m_rsp_secret_buffer, ((spdm_secured_message_context_t
              *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == SPDM_ERROR_CODE_RESERVED_0D) {
            error_code = SPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = SPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

spdm_test_context_t m_spdm_requester_key_update_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    TRUE,
    spdm_requester_key_update_test_send_message,
    spdm_requester_key_update_test_receive_message,
};

int spdm_requester_key_update_test_main(void)
{
    const struct CMUnitTest spdm_requester_key_update_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(test_spdm_requester_key_update_case1),
        /* update single key*/
        /* Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case2),
        /* connection_state check failed*/
        cmocka_unit_test(test_spdm_requester_key_update_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_key_update_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_key_update_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_key_update_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_key_update_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case9),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_key_update_case10),
        /* Buffer reset*/
        cmocka_unit_test(test_spdm_requester_key_update_case11),
        /* No correct setup*/
        cmocka_unit_test(test_spdm_requester_key_update_case12),
        cmocka_unit_test(test_spdm_requester_key_update_case13),
        cmocka_unit_test(test_spdm_requester_key_update_case14),
        /* Wrong parameters*/
        cmocka_unit_test(test_spdm_requester_key_update_case15),
        cmocka_unit_test(test_spdm_requester_key_update_case16),
        /* verify key*/
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_key_update_case17),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_key_update_case18),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case19),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_key_update_case20),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_key_update_case21),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case22),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_key_update_case23),
        /* No correct setup*/
        cmocka_unit_test(test_spdm_requester_key_update_case24),
        /* Wrong parameters*/
        cmocka_unit_test(test_spdm_requester_key_update_case25),
        cmocka_unit_test(test_spdm_requester_key_update_case26),
        /* update all keys*/
        /* Sucessful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case27),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_requester_key_update_case28),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(test_spdm_requester_key_update_case29),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case30),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(test_spdm_requester_key_update_case31),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(test_spdm_requester_key_update_case32),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(test_spdm_requester_key_update_case33),
        /* Unexpected errors*/
        cmocka_unit_test(test_spdm_requester_key_update_case34),
    };

    setup_spdm_test_context(&m_spdm_requester_key_update_test_context);

    return cmocka_run_group_tests(spdm_requester_key_update_tests,
                      spdm_unit_test_group_setup,
                      spdm_unit_test_group_teardown);
}
