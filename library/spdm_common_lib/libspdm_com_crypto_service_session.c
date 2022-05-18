/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates current TH data with message A and message K.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
 * @param  th_data_buffer_size             size in bytes of the th_data_buffer
 * @param  th_data_buffer                 The buffer to store the th_data_buffer
 *
 * @retval RETURN_SUCCESS  current TH data is calculated.
 */
bool libspdm_calculate_th_for_exchange(
    void *context, void *spdm_session_info, const uint8_t *cert_chain_buffer,
    size_t cert_chain_buffer_size,
    size_t *th_data_buffer_size, void *th_data_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t hash_size;
    libspdm_return_t status;
    libspdm_large_managed_buffer_t th_curr;
    bool result;
    size_t th_data_buffer_capacity;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_data_buffer_size >= LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    libspdm_init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_a data :\n"));
    libspdm_internal_dump_hex(
        libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
        libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    status = libspdm_append_managed_buffer(
        &th_curr,
        libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
        libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (cert_chain_buffer != NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_message_ct data :\n"));
        libspdm_internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
        result = libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_chain_buffer, cert_chain_buffer_size,
            cert_chain_buffer_hash);
        if (!result) {
            return false;
        }
        status = libspdm_append_managed_buffer(&th_curr, cert_chain_buffer_hash,
                                               hash_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_k data :\n"));
    libspdm_internal_dump_hex(
        libspdm_get_managed_buffer(&session_info->session_transcript.message_k),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    status = libspdm_append_managed_buffer(
        &th_curr,
        libspdm_get_managed_buffer(&session_info->session_transcript.message_k),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    th_data_buffer_capacity = *th_data_buffer_size;
    *th_data_buffer_size = libspdm_get_managed_buffer_size(&th_curr);
    libspdm_copy_mem(th_data_buffer, th_data_buffer_capacity,
                     libspdm_get_managed_buffer(&th_curr), *th_data_buffer_size);

    return true;
}
#else
/*
 * This function calculates current TH hash with message A and message K.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
 * @param  th_hash_buffer                 The buffer to store the th_hash_buffer
 *
 * @retval RETURN_SUCCESS  current TH hash is calculated.
 */
bool libspdm_calculate_th_hash_for_exchange(
    void *context, void *spdm_session_info,
    size_t *th_hash_buffer_size, void *th_hash_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t hash_size;
    void *digest_context_th;
    bool result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_hash_buffer_size >= hash_size);

    /* duplicate the th context, because we still need use original context to continue.*/
    digest_context_th = libspdm_hash_new (
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (digest_context_th == NULL) {
        return false;
    }
    result = libspdm_hash_duplicate (spdm_context->connection_info.algorithm.base_hash_algo,
                                     session_info->session_transcript.digest_context_th,
                                     digest_context_th);
    if (!result) {
        libspdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
                           digest_context_th);
        return false;
    }
    result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                 digest_context_th, th_hash_buffer);
    libspdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
    if (!result) {
        return false;
    }

    *th_hash_buffer_size = hash_size;

    return true;
}

/*
 * This function calculates current TH hmac with message A and message K, with response finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_exchange_rsp(
    void *context, void *spdm_session_info, bool is_requester,
    size_t *th_hmac_buffer_size, void *th_hmac_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    libspdm_return_t status;
    bool result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_hmac_buffer_size >= hash_size);

    if (session_info->session_transcript.hmac_rsp_context_th == NULL) {
        /* trigger message_k to initialize hmac context after finished_key is ready.*/
        status = libspdm_append_message_k (context, spdm_session_info, is_requester, NULL, 0);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
        LIBSPDM_ASSERT(session_info->session_transcript.hmac_rsp_context_th != NULL);
    }

    /* duplicate the th context, because we still need use original context to continue.*/
    hmac_context_th = libspdm_hmac_new_with_response_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return false;
    }
    result = libspdm_hmac_duplicate_with_response_finished_key (secured_message_context,
                                                                session_info->session_transcript.hmac_rsp_context_th,
                                                                hmac_context_th);
    if (!result) {
        libspdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
        return false;
    }
    result = libspdm_hmac_final_with_response_finished_key (secured_message_context,
                                                            hmac_context_th, th_hmac_buffer);
    libspdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return false;
    }

    *th_hmac_buffer_size = hash_size;

    return true;
}
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates current TH data with message A, message K and message F.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
 * @param  mut_cert_chain_buffer             Certitiface chain buffer with spdm_cert_chain_t header in mutual authentication.
 * @param  mut_cert_chain_buffer_size         size in bytes of the certitiface chain buffer in mutual authentication.
 * @param  th_data_buffer_size             size in bytes of the th_data_buffer
 * @param  th_data_buffer                 The buffer to store the th_data_buffer
 *
 * @retval RETURN_SUCCESS  current TH data is calculated.
 */
bool libspdm_calculate_th_for_finish(void *context,
                                     void *spdm_session_info,
                                     const uint8_t *cert_chain_buffer,
                                     size_t cert_chain_buffer_size,
                                     const uint8_t *mut_cert_chain_buffer,
                                     size_t mut_cert_chain_buffer_size,
                                     size_t *th_data_buffer_size,
                                     void *th_data_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t mut_cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t hash_size;
    libspdm_return_t status;
    libspdm_large_managed_buffer_t th_curr;
    bool result;
    size_t th_data_buffer_capacity;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_data_buffer_size >= LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
    libspdm_init_managed_buffer(&th_curr, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_a data :\n"));
    libspdm_internal_dump_hex(
        libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
        libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    status = libspdm_append_managed_buffer(
        &th_curr,
        libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
        libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (cert_chain_buffer != NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_message_ct data :\n"));
        libspdm_internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
        result = libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_chain_buffer, cert_chain_buffer_size,
            cert_chain_buffer_hash);
        if (!result) {
            return false;
        }
        status = libspdm_append_managed_buffer(&th_curr, cert_chain_buffer_hash,
                                               hash_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_k data :\n"));
    libspdm_internal_dump_hex(
        libspdm_get_managed_buffer(&session_info->session_transcript.message_k),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    status = libspdm_append_managed_buffer(
        &th_curr,
        libspdm_get_managed_buffer(&session_info->session_transcript.message_k),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (mut_cert_chain_buffer != NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_message_cm data :\n"));
        libspdm_internal_dump_hex(mut_cert_chain_buffer,
                                  mut_cert_chain_buffer_size);
        result = libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            mut_cert_chain_buffer, mut_cert_chain_buffer_size,
            mut_cert_chain_buffer_hash);
        if (!result) {
            return false;
        }
        status = libspdm_append_managed_buffer(&th_curr, mut_cert_chain_buffer_hash,
                                               hash_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "message_f data :\n"));
    libspdm_internal_dump_hex(
        libspdm_get_managed_buffer(&session_info->session_transcript.message_f),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_f));
    status = libspdm_append_managed_buffer(
        &th_curr,
        libspdm_get_managed_buffer(&session_info->session_transcript.message_f),
        libspdm_get_managed_buffer_size(
            &session_info->session_transcript.message_f));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    th_data_buffer_capacity = *th_data_buffer_size;
    *th_data_buffer_size = libspdm_get_managed_buffer_size(&th_curr);
    libspdm_copy_mem(th_data_buffer, th_data_buffer_capacity,
                     libspdm_get_managed_buffer(&th_curr), *th_data_buffer_size);

    return true;
}
#else
/*
 * This function calculates current TH hash with message A, message K and message F.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
 * @param  th_hash_buffer                 The buffer to store the th_hash_buffer
 *
 * @retval RETURN_SUCCESS  current TH hash is calculated.
 */
bool libspdm_calculate_th_hash_for_finish(void *context,
                                          void *spdm_session_info,
                                          size_t *th_hash_buffer_size,
                                          void *th_hash_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t hash_size;
    void *digest_context_th;
    bool result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_hash_buffer_size >= hash_size);

    /* duplicate the th context, because we still need use original context to continue.*/
    digest_context_th = libspdm_hash_new (
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (digest_context_th == NULL) {
        return false;
    }
    result = libspdm_hash_duplicate (spdm_context->connection_info.algorithm.base_hash_algo,
                                     session_info->session_transcript.digest_context_th,
                                     digest_context_th);
    if (!result) {
        libspdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo,
                           digest_context_th);
        return false;
    }
    result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                 digest_context_th, th_hash_buffer);
    libspdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
    if (!result) {
        return false;
    }

    *th_hash_buffer_size = hash_size;

    return true;
}

/*
 * This function calculates current TH hmac with message A, message K and message F, with response finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_finish_rsp(void *context,
                                              void *spdm_session_info,
                                              size_t *th_hmac_buffer_size,
                                              void *th_hmac_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    bool result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_hmac_buffer_size >= hash_size);

    LIBSPDM_ASSERT(session_info->session_transcript.hmac_rsp_context_th != NULL);

    /* duplicate the th context, because we still need use original context to continue.*/
    hmac_context_th = libspdm_hmac_new_with_response_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return false;
    }
    result = libspdm_hmac_duplicate_with_response_finished_key (secured_message_context,
                                                                session_info->session_transcript.hmac_rsp_context_th,
                                                                hmac_context_th);
    if (!result) {
        libspdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
        return false;
    }
    result = libspdm_hmac_final_with_response_finished_key (secured_message_context,
                                                            hmac_context_th, th_hmac_buffer);
    libspdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return false;
    }

    *th_hmac_buffer_size = hash_size;

    return true;
}

/*
 * This function calculates current TH hmac with message A, message K and message F, with request finished_key.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
 * @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer
 *
 * @retval RETURN_SUCCESS  current TH hmac is calculated.
 */
bool libspdm_calculate_th_hmac_for_finish_req(void *context,
                                              void *spdm_session_info,
                                              size_t *th_hmac_buffer_size,
                                              void *th_hmac_buffer)
{
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    bool result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    LIBSPDM_ASSERT(*th_hmac_buffer_size >= hash_size);

    LIBSPDM_ASSERT(session_info->session_transcript.hmac_req_context_th != NULL);

    /* duplicate the th context, because we still need use original context to continue.*/
    hmac_context_th = libspdm_hmac_new_with_request_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return false;
    }
    result = libspdm_hmac_duplicate_with_request_finished_key (secured_message_context,
                                                               session_info->session_transcript.hmac_req_context_th,
                                                               hmac_context_th);
    if (!result) {
        libspdm_hmac_free_with_request_finished_key (secured_message_context, hmac_context_th);
        return false;
    }
    result = libspdm_hmac_final_with_request_finished_key (secured_message_context,
                                                           hmac_context_th, th_hmac_buffer);
    libspdm_hmac_free_with_request_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return false;
    }

    *th_hmac_buffer_size = hash_size;

    return true;
}
#endif

/**
 * This function generates the key exchange signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  signature                    The buffer to store the key exchange signature.
 *
 * @retval true  key exchange signature is generated.
 * @retval false key exchange signature is not generated.
 **/
bool
libspdm_generate_key_exchange_rsp_signature(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            uint8_t *signature)
{
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    const uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    bool result;
    size_t signature_size;
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    /* Debug code only - required for debug print of th_curr hash below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    libspdm_internal_dump_data(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        false, th_curr_data, th_curr_data_size, signature, &signature_size);
#else
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        true, hash_data, hash_size, signature, &signature_size);
#endif
    if (result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
        libspdm_internal_dump_data(signature, signature_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }
    return result;
}

/**
 * This function generates the key exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the key exchange HMAC.
 *
 * @retval true  key exchange HMAC is generated.
 * @retval false key exchange HMAC is not generated.
 **/
bool
libspdm_generate_key_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif
    bool result;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, false, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

/**
 * This function verifies the key exchange signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_key_exchange_rsp_signature(
    libspdm_context_t *spdm_context, libspdm_session_info_t *session_info,
    const void *sign_data, const size_t sign_data_size)
{
    size_t hash_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    const uint8_t *cert_chain_data;
    size_t cert_chain_data_size;
    const uint8_t *cert_buffer;
    size_t cert_buffer_size;
    void *context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#else
    uint8_t slot_id;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    /* Debug code only - required for debug print of th_curr hash below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    libspdm_internal_dump_data(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
    libspdm_internal_dump_data(sign_data, sign_data_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

 #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* Get leaf cert from cert chain*/

    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (const void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return false;
    }
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data,
                                                   cert_chain_data_size, -1,
                                                   &cert_buffer, &cert_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_asym_get_public_key_from_x509(
        spdm_context->connection_info.algorithm.base_asym_algo,
        cert_buffer, cert_buffer_size, &context);
    if (!result) {
        return false;
    }

    result = libspdm_asym_verify(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        th_curr_data, th_curr_data_size, sign_data, sign_data_size);
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      context);
#else
    slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
    if (spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key != NULL) {
        result = libspdm_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key,
            hash_data, hash_size, sign_data, sign_data_size);
    } else {
        /* Get leaf cert from cert chain*/
        result = libspdm_get_peer_cert_chain_data(
            spdm_context, (const void **)&cert_chain_data, &cert_chain_data_size);
        if (!result) {
            return false;
        }
        result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data,
                                                       cert_chain_data_size, -1,
                                                       &cert_buffer, &cert_buffer_size);
        if (!result) {
            return false;
        }

        result = libspdm_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm.base_asym_algo,
            cert_buffer, cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo, context,
            hash_data, hash_size, sign_data, sign_data_size);
        libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                          context);
    }
#endif
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! verify_key_exchange_signature - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_key_exchange_signature - PASS !!!\n"));

    return true;
}

/**
 * This function verifies the key exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_key_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          const void *hmac_data,
                                          size_t hmac_data_size)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hash_size == hmac_data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, true, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (libspdm_const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! verify_key_exchange_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_key_exchange_hmac - PASS !!!\n"));

    return true;
}

/**
 * This function generates the finish signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  signature                    The buffer to store the finish signature.
 *
 * @retval true  finish signature is generated.
 * @retval false finish signature is not generated.
 **/
bool libspdm_generate_finish_req_signature(libspdm_context_t *spdm_context,
                                           libspdm_session_info_t *session_info,
                                           uint8_t *signature)
{
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    size_t signature_size;
    size_t hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    signature_size = libspdm_get_req_asym_signature_size(
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_get_local_cert_chain_buffer(spdm_context,
                                                 (const void **)&mut_cert_chain_buffer,
                                                 &mut_cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    /* Debug code only - required for debug print of th_curr below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    libspdm_internal_dump_data(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_requester_data_sign(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        false, th_curr_data, th_curr_data_size, signature, &signature_size);
#else
    result = libspdm_requester_data_sign(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        true, hash_data, hash_size, signature, &signature_size);
#endif
    if (result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
        libspdm_internal_dump_data(signature, signature_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    return result;
}

/**
 * This function generates the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  finish HMAC is generated.
 * @retval false finish HMAC is not generated.
 **/
bool libspdm_generate_finish_req_hmac(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t *session_info,
                                      void *hmac)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, calc_hmac_data, hash_size);

    return true;
}

/**
 * This function verifies the finish signature based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool libspdm_verify_finish_req_signature(libspdm_context_t *spdm_context,
                                         libspdm_session_info_t *session_info,
                                         const void *sign_data,
                                         const size_t sign_data_size)
{
    size_t hash_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    const uint8_t *mut_cert_chain_data;
    size_t mut_cert_chain_data_size;
    const uint8_t *mut_cert_buffer;
    size_t mut_cert_buffer_size;
    void *context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#else
    uint8_t slot_id;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_get_peer_cert_chain_buffer(spdm_context,
                                                (const void **)&mut_cert_chain_buffer,
                                                &mut_cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    /* Debug code only - required for debug print of th_curr below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    libspdm_internal_dump_data(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
    libspdm_internal_dump_data(sign_data, sign_data_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* Get leaf cert from cert chain*/

    result = libspdm_get_peer_cert_chain_data(spdm_context,
                                              (const void **)&mut_cert_chain_data,
                                              &mut_cert_chain_data_size);
    if (!result) {
        return false;
    }
    result = libspdm_x509_get_cert_from_cert_chain(mut_cert_chain_data,
                                                   mut_cert_chain_data_size, -1,
                                                   &mut_cert_buffer,
                                                   &mut_cert_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_req_asym_get_public_key_from_x509(
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        mut_cert_buffer, mut_cert_buffer_size, &context);
    if (!result) {
        return false;
    }

    result = libspdm_req_asym_verify(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        th_curr_data, th_curr_data_size, sign_data, sign_data_size);
    libspdm_req_asym_free(
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        context);
#else
    slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
    if (spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key != NULL) {
        result = libspdm_req_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_FINISH,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key,
            hash_data, hash_size, sign_data, sign_data_size);
    } else {
        /* Get leaf cert from cert chain*/
        result = libspdm_get_peer_cert_chain_data(spdm_context,
                                                  (const void **)&mut_cert_chain_data,
                                                  &mut_cert_chain_data_size);
        if (!result) {
            return false;
        }
        result = libspdm_x509_get_cert_from_cert_chain(mut_cert_chain_data,
                                                       mut_cert_chain_data_size, -1,
                                                       &mut_cert_buffer,
                                                       &mut_cert_buffer_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            mut_cert_buffer, mut_cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_FINISH,
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo, context,
            hash_data, hash_size, sign_data, sign_data_size);
        libspdm_req_asym_free(
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            context);
    }
#endif

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! VerifyFinishSignature - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

    return true;
}

/**
 * This function verifies the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_finish_req_hmac(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    const uint8_t *hmac, size_t hmac_size)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hmac_size == hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_peer_cert_chain_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (libspdm_const_compare_mem(hmac, hmac_data, hash_size) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_finish_req_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_finish_req_hmac - PASS !!!\n"));
    return true;
}

/**
 * This function generates the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  finish HMAC is generated.
 * @retval false finish HMAC is not generated.
 **/
bool libspdm_generate_finish_rsp_hmac(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t *session_info,
                                      uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_peer_cert_chain_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_rsp(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

/**
 * This function verifies the finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_finish_rsp_hmac(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    const void *hmac_data, size_t hmac_data_size)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hash_size == hmac_data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_rsp(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (libspdm_const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_finish_rsp_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_finish_rsp_hmac - PASS !!!\n"));

    return true;
}

/**
 * This function generates the PSK exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the PSK exchange HMAC.
 *
 * @retval true  PSK exchange HMAC is generated.
 * @retval false PSK exchange HMAC is not generated.
 **/
bool
libspdm_generate_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(spdm_context, session_info,
                                               NULL, 0, &th_curr_data_size,
                                               th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, false, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

/**
 * This function verifies the PSK exchange HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_psk_exchange_rsp_hmac(libspdm_context_t *spdm_context,
                                          libspdm_session_info_t *session_info,
                                          const void *hmac_data,
                                          size_t hmac_data_size)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hash_size == hmac_data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(spdm_context, session_info,
                                               NULL, 0, &th_curr_data_size,
                                               th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, true, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (libspdm_const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! verify_psk_exchange_rsp_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_psk_exchange_rsp_hmac - PASS !!!\n"));

    return true;
}

/**
 * This function generates the PSK finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  PSK finish HMAC is generated.
 * @retval false PSK finish HMAC is not generated.
 **/
bool
libspdm_generate_psk_exchange_req_hmac(libspdm_context_t *spdm_context,
                                       libspdm_session_info_t *session_info,
                                       void *hmac)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(spdm_context, session_info, NULL,
                                             0, NULL, 0, &th_curr_data_size,
                                             th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    libspdm_internal_dump_data(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, calc_hmac_data, hash_size);

    return true;
}

/**
 * This function verifies the PSK finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac_data                     The HMAC data buffer.
 * @param  hmac_data_size                 size in bytes of the HMAC data buffer.
 *
 * @retval true  HMAC verification pass.
 * @retval false HMAC verification fail.
 **/
bool libspdm_verify_psk_finish_req_hmac(libspdm_context_t *spdm_context,
                                        libspdm_session_info_t *session_info,
                                        const uint8_t *hmac, size_t hmac_size)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hmac_size == hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(spdm_context, session_info, NULL,
                                             0, NULL, 0, &th_curr_data_size,
                                             th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc th_curr hmac - "));
    libspdm_internal_dump_data(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (libspdm_const_compare_mem(hmac, hmac_data, hash_size) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "!!! verify_psk_finish_req_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_psk_finish_req_hmac - PASS !!!\n"));
    return true;
}

/*
 * This function calculates th1 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  th1_hash_data                  th1 hash
 *
 * @retval RETURN_SUCCESS  th1 hash is calculated.
 */
bool libspdm_calculate_th1_hash(void *context,
                                void *spdm_session_info,
                                bool is_requester,
                                uint8_t *th1_hash_data)
{
    libspdm_context_t *spdm_context;
    size_t hash_size;
    libspdm_session_info_t *session_info;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    spdm_context = context;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc th1 hash ...\n"));

    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    if (!session_info->use_psk) {
        if (is_requester) {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (const void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        } else {
            result = libspdm_get_local_cert_chain_buffer(
                spdm_context, (const void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        }
        if (!result) {
            return false;
        }
    } else {
        cert_chain_buffer = NULL;
        cert_chain_buffer_size = 0;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
                              th_curr_data, th_curr_data_size, th1_hash_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, th1_hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th1 hash - "));
    libspdm_internal_dump_data(th1_hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    return true;
}

/*
 * This function calculates th2 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The SPDM session ID.
 * @param  is_requester                  Indicate of the key generation for a requester or a responder.
 * @param  th1_hash_data                  th2 hash
 *
 * @retval RETURN_SUCCESS  th2 hash is calculated.
 */
bool libspdm_calculate_th2_hash(void *context,
                                void *spdm_session_info,
                                bool is_requester,
                                uint8_t *th2_hash_data)
{
    libspdm_context_t *spdm_context;
    size_t hash_size;
    libspdm_session_info_t *session_info;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t th_curr_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t th_curr_data_size;
#endif

    spdm_context = context;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc th2 hash ...\n"));

    session_info = spdm_session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    if (!session_info->use_psk) {
        if (is_requester) {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (const void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        } else {
            result = libspdm_get_local_cert_chain_buffer(
                spdm_context, (const void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        }
        if (!result) {
            return false;
        }
        if (session_info->mut_auth_requested) {
            if (is_requester) {
                result = libspdm_get_local_cert_chain_buffer(
                    spdm_context,
                    (const void **)&mut_cert_chain_buffer,
                    &mut_cert_chain_buffer_size);
            } else {
                result = libspdm_get_peer_cert_chain_buffer(
                    spdm_context,
                    (const void **)&mut_cert_chain_buffer,
                    &mut_cert_chain_buffer_size);
            }
            if (!result) {
                return false;
            }
        } else {
            mut_cert_chain_buffer = NULL;
            mut_cert_chain_buffer_size = 0;
        }
    } else {
        cert_chain_buffer = NULL;
        cert_chain_buffer_size = 0;
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return false;
    }

    result = libspdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
                              th_curr_data, th_curr_data_size, th2_hash_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, th2_hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th2 hash - "));
    libspdm_internal_dump_data(th2_hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    return true;
}
