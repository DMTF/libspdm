/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
  This function calculates current TH data with message A and message K.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
  @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean libspdm_calculate_th_for_exchange(
    IN void *context, IN void *spdm_session_info, IN uint8_t *cert_chain_buffer,
    OPTIONAL IN uintn cert_chain_buffer_size,
    OPTIONAL IN OUT uintn *th_data_buffer_size, OUT void *th_data_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint8_t cert_chain_buffer_hash[MAX_HASH_SIZE];
    uint32_t hash_size;
    return_status status;
    large_managed_buffer_t th_curr;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_data_buffer_size >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
    init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

    DEBUG((DEBUG_INFO, "message_a data :\n"));
    internal_dump_hex(
        get_managed_buffer(&spdm_context->transcript.message_a),
        get_managed_buffer_size(&spdm_context->transcript.message_a));
    status = append_managed_buffer(
        &th_curr,
        get_managed_buffer(&spdm_context->transcript.message_a),
        get_managed_buffer_size(&spdm_context->transcript.message_a));
    if (RETURN_ERROR(status)) {
        return FALSE;
    }

    if (cert_chain_buffer != NULL) {
        DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
        internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
        result = spdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_chain_buffer, cert_chain_buffer_size,
            cert_chain_buffer_hash);
        if (!result) {
            return FALSE;
        }
        status = append_managed_buffer(&th_curr, cert_chain_buffer_hash,
                           hash_size);
        if (RETURN_ERROR(status)) {
            return FALSE;
        }
    }

    DEBUG((DEBUG_INFO, "message_k data :\n"));
    internal_dump_hex(
        get_managed_buffer(&session_info->session_transcript.message_k),
        get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    status = append_managed_buffer(
        &th_curr,
        get_managed_buffer(&session_info->session_transcript.message_k),
        get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    if (RETURN_ERROR(status)) {
        return FALSE;
    }

    *th_data_buffer_size = get_managed_buffer_size(&th_curr);
    copy_mem(th_data_buffer, get_managed_buffer(&th_curr),
         *th_data_buffer_size);

    return TRUE;
}
#else
/*
  This function calculates current TH hash with message A and message K.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
  @param  th_hash_buffer                 The buffer to store the th_hash_buffer

  @retval RETURN_SUCCESS  current TH hash is calculated.
*/
boolean libspdm_calculate_th_hash_for_exchange(
    IN void *context, IN void *spdm_session_info,
    OPTIONAL IN OUT uintn *th_hash_buffer_size, OUT void *th_hash_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint32_t hash_size;
    void *digest_context_th;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_hash_buffer_size >= hash_size);

    // duplicate the th context, because we still need use original context to continue.
    digest_context_th = spdm_hash_new (
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (digest_context_th == NULL) {
        return FALSE;
    }
    result = spdm_hash_duplicate (spdm_context->connection_info.algorithm.base_hash_algo,
        session_info->session_transcript.digest_context_th, digest_context_th);
    if (!result) {
        spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
        return FALSE;
    }
    result = spdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
        digest_context_th, th_hash_buffer);
    spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
    if (!result) {
        return FALSE;
    }

    *th_hash_buffer_size = hash_size;

    return TRUE;
}

/*
  This function calculates current TH hmac with message A and message K, with response finished_key.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
  @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer

  @retval RETURN_SUCCESS  current TH hmac is calculated.
*/
boolean libspdm_calculate_th_hmac_for_exchange_rsp(
    IN void *context, IN void *spdm_session_info, IN boolean is_requester,
    OPTIONAL IN OUT uintn *th_hmac_buffer_size, OUT void *th_hmac_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    return_status status;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_hmac_buffer_size >= hash_size);

    if (session_info->session_transcript.hmac_rsp_context_th == NULL) {
        // trigger message_k to initialize hmac context after finished_key is ready.
        status = libspdm_append_message_k (context, spdm_session_info, is_requester, NULL, 0);
        if (RETURN_ERROR(status)) {
            return FALSE;
        }
        ASSERT(session_info->session_transcript.hmac_rsp_context_th != NULL);
    }

    // duplicate the th context, because we still need use original context to continue.
    hmac_context_th = spdm_hmac_new_with_response_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return FALSE;
    }
    result = spdm_hmac_duplicate_with_response_finished_key (secured_message_context,
        session_info->session_transcript.hmac_rsp_context_th, hmac_context_th);
    if (!result) {
        spdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
        return FALSE;
    }
    result = spdm_hmac_final_with_response_finished_key (secured_message_context,
        hmac_context_th, th_hmac_buffer);
    spdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return FALSE;
    }

    *th_hmac_buffer_size = hash_size;

    return TRUE;
}
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
  This function calculates current TH data with message A, message K and message F.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  cert_chain_buffer                Certitiface chain buffer with spdm_cert_chain_t header.
  @param  cert_chain_buffer_size            size in bytes of the certitiface chain buffer.
  @param  mut_cert_chain_buffer             Certitiface chain buffer with spdm_cert_chain_t header in mutual authentication.
  @param  mut_cert_chain_buffer_size         size in bytes of the certitiface chain buffer in mutual authentication.
  @param  th_data_buffer_size             size in bytes of the th_data_buffer
  @param  th_data_buffer                 The buffer to store the th_data_buffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
boolean libspdm_calculate_th_for_finish(IN void *context,
                     IN void *spdm_session_info,
                     IN uint8_t *cert_chain_buffer,
                     OPTIONAL IN uintn cert_chain_buffer_size,
                     OPTIONAL IN uint8_t *mut_cert_chain_buffer,
                     OPTIONAL IN uintn mut_cert_chain_buffer_size,
                     OPTIONAL IN OUT uintn *th_data_buffer_size,
                     OUT void *th_data_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint8_t cert_chain_buffer_hash[MAX_HASH_SIZE];
    uint8_t mut_cert_chain_buffer_hash[MAX_HASH_SIZE];
    uint32_t hash_size;
    return_status status;
    large_managed_buffer_t th_curr;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_data_buffer_size >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
    init_managed_buffer(&th_curr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

    DEBUG((DEBUG_INFO, "message_a data :\n"));
    internal_dump_hex(
        get_managed_buffer(&spdm_context->transcript.message_a),
        get_managed_buffer_size(&spdm_context->transcript.message_a));
    status = append_managed_buffer(
        &th_curr,
        get_managed_buffer(&spdm_context->transcript.message_a),
        get_managed_buffer_size(&spdm_context->transcript.message_a));
    if (RETURN_ERROR(status)) {
        return FALSE;
    }

    if (cert_chain_buffer != NULL) {
        DEBUG((DEBUG_INFO, "th_message_ct data :\n"));
        internal_dump_hex(cert_chain_buffer, cert_chain_buffer_size);
        result = spdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_chain_buffer, cert_chain_buffer_size,
            cert_chain_buffer_hash);
        if (!result) {
            return FALSE;
        }
        status = append_managed_buffer(&th_curr, cert_chain_buffer_hash,
                           hash_size);
        if (RETURN_ERROR(status)) {
            return FALSE;
        }
    }

    DEBUG((DEBUG_INFO, "message_k data :\n"));
    internal_dump_hex(
        get_managed_buffer(&session_info->session_transcript.message_k),
        get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    status = append_managed_buffer(
        &th_curr,
        get_managed_buffer(&session_info->session_transcript.message_k),
        get_managed_buffer_size(
            &session_info->session_transcript.message_k));
    if (RETURN_ERROR(status)) {
        return FALSE;
    }

    if (mut_cert_chain_buffer != NULL) {
        DEBUG((DEBUG_INFO, "th_message_cm data :\n"));
        internal_dump_hex(mut_cert_chain_buffer,
                  mut_cert_chain_buffer_size);
        result = spdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            mut_cert_chain_buffer, mut_cert_chain_buffer_size,
            mut_cert_chain_buffer_hash);
        if (!result) {
            return FALSE;
        }
        status = append_managed_buffer(&th_curr, mut_cert_chain_buffer_hash,
                           hash_size);
        if (RETURN_ERROR(status)) {
            return FALSE;
        }
    }

    DEBUG((DEBUG_INFO, "message_f data :\n"));
    internal_dump_hex(
        get_managed_buffer(&session_info->session_transcript.message_f),
        get_managed_buffer_size(
            &session_info->session_transcript.message_f));
    status = append_managed_buffer(
        &th_curr,
        get_managed_buffer(&session_info->session_transcript.message_f),
        get_managed_buffer_size(
            &session_info->session_transcript.message_f));
    if (RETURN_ERROR(status)) {
        return FALSE;
    }

    *th_data_buffer_size = get_managed_buffer_size(&th_curr);
    copy_mem(th_data_buffer, get_managed_buffer(&th_curr),
         *th_data_buffer_size);

    return TRUE;
}
#else
/*
  This function calculates current TH hash with message A, message K and message F.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  th_hash_buffer_size             size in bytes of the th_hash_buffer
  @param  th_hash_buffer                 The buffer to store the th_hash_buffer

  @retval RETURN_SUCCESS  current TH hash is calculated.
*/
boolean libspdm_calculate_th_hash_for_finish(IN void *context,
                     IN void *spdm_session_info,
                     OPTIONAL IN OUT uintn *th_hash_buffer_size,
                     OUT void *th_hash_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    uint32_t hash_size;
    void *digest_context_th;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_hash_buffer_size >= hash_size);

    // duplicate the th context, because we still need use original context to continue.
    digest_context_th = spdm_hash_new (
        spdm_context->connection_info.algorithm.base_hash_algo);
    if (digest_context_th == NULL) {
        return FALSE;
    }
    result = spdm_hash_duplicate (spdm_context->connection_info.algorithm.base_hash_algo,
        session_info->session_transcript.digest_context_th, digest_context_th);
    if (!result) {
        spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
        return FALSE;
    }
    result = spdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
        digest_context_th, th_hash_buffer);
    spdm_hash_free (spdm_context->connection_info.algorithm.base_hash_algo, digest_context_th);
    if (!result) {
        return FALSE;
    }

    *th_hash_buffer_size = hash_size;

    return TRUE;
}

/*
  This function calculates current TH hmac with message A, message K and message F, with response finished_key.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
  @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer

  @retval RETURN_SUCCESS  current TH hmac is calculated.
*/
boolean libspdm_calculate_th_hmac_for_finish_rsp(IN void *context,
                     IN void *spdm_session_info,
                     OPTIONAL IN OUT uintn *th_hmac_buffer_size,
                     OUT void *th_hmac_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_hmac_buffer_size >= hash_size);

    ASSERT(session_info->session_transcript.hmac_rsp_context_th != NULL);

    // duplicate the th context, because we still need use original context to continue.
    hmac_context_th = spdm_hmac_new_with_response_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return FALSE;
    }
    result = spdm_hmac_duplicate_with_response_finished_key (secured_message_context,
        session_info->session_transcript.hmac_rsp_context_th, hmac_context_th);
    if (!result) {
        spdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
        return FALSE;
    }
    result = spdm_hmac_final_with_response_finished_key (secured_message_context,
        hmac_context_th, th_hmac_buffer);
    spdm_hmac_free_with_response_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return FALSE;
    }

    *th_hmac_buffer_size = hash_size;

    return TRUE;
}

/*
  This function calculates current TH hmac with message A, message K and message F, with request finished_key.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  th_hmac_buffer_size             size in bytes of the th_hmac_buffer
  @param  th_hmac_buffer                 The buffer to store the th_hmac_buffer

  @retval RETURN_SUCCESS  current TH hmac is calculated.
*/
boolean libspdm_calculate_th_hmac_for_finish_req(IN void *context,
                     IN void *spdm_session_info,
                     OPTIONAL IN OUT uintn *th_hmac_buffer_size,
                     OUT void *th_hmac_buffer)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *session_info;
    void *secured_message_context;
    uint32_t hash_size;
    void *hmac_context_th;
    boolean result;

    spdm_context = context;
    session_info = spdm_session_info;
    secured_message_context = session_info->secured_message_context;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    ASSERT(*th_hmac_buffer_size >= hash_size);

    ASSERT(session_info->session_transcript.hmac_req_context_th != NULL);

    // duplicate the th context, because we still need use original context to continue.
    hmac_context_th = spdm_hmac_new_with_request_finished_key (secured_message_context);
    if (hmac_context_th == NULL) {
        return FALSE;
    }
    result = spdm_hmac_duplicate_with_request_finished_key (secured_message_context,
        session_info->session_transcript.hmac_req_context_th, hmac_context_th);
    if (!result) {
        spdm_hmac_free_with_request_finished_key (secured_message_context, hmac_context_th);
        return FALSE;
    }
    result = spdm_hmac_final_with_request_finished_key (secured_message_context,
        hmac_context_th, th_hmac_buffer);
    spdm_hmac_free_with_request_finished_key (secured_message_context, hmac_context_th);
    if (!result) {
        return FALSE;
    }

    *th_hmac_buffer_size = hash_size;

    return TRUE;
}
#endif

/**
  This function generates the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_signature(IN spdm_context_t *spdm_context,
                     IN spdm_session_info_t *session_info,
                     OUT uint8_t *signature)
{
    uint8_t hash_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    boolean result;
    uintn signature_size;
    uintn hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    signature_size = spdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    // Debug code only - required for debug print of th_curr hash below
    DEBUG_CODE(
        if (!spdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
            return FALSE;
        }
    );
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hash - "));
    internal_dump_data(hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = spdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        FALSE, th_curr_data, th_curr_data_size, signature, &signature_size);
#else
    result = spdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        TRUE, hash_data, hash_size, signature, &signature_size);
#endif
    if (result) {
        DEBUG((DEBUG_INFO, "signature - "));
        internal_dump_data(signature, signature_size);
        DEBUG((DEBUG_INFO, "\n"));
    }
    return result;
}

/**
  This function generates the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
boolean
spdm_generate_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    OUT uint8_t *hmac)
{
    uint8_t hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uintn hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif
    boolean result;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, FALSE, &hash_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));
    copy_mem(hmac, hmac_data, hash_size);

    return TRUE;
}

/**
  This function verifies the key exchange signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_key_exchange_rsp_signature(
    IN spdm_context_t *spdm_context, IN spdm_session_info_t *session_info,
    IN void *sign_data, IN intn sign_data_size)
{
    uintn hash_size;
    uint8_t hash_data[MAX_HASH_SIZE];
    boolean result;
    uint8_t *cert_chain_data;
    uintn cert_chain_data_size;
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    void *context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    // Debug code only - required for debug print of th_curr hash below
    DEBUG_CODE(
        if (!spdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
            return FALSE;
        }
    );
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hash - "));
    internal_dump_data(hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    DEBUG((DEBUG_INFO, "signature - "));
    internal_dump_data(sign_data, sign_data_size);
    DEBUG((DEBUG_INFO, "\n"));

    //
    // Get leaf cert from cert chain
    //
    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return FALSE;
    }
    result = x509_get_cert_from_cert_chain(cert_chain_data,
                           cert_chain_data_size, -1,
                           &cert_buffer, &cert_buffer_size);
    if (!result) {
        return FALSE;
    }

    result = spdm_asym_get_public_key_from_x509(
        spdm_context->connection_info.algorithm.base_asym_algo,
        cert_buffer, cert_buffer_size, &context);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = spdm_asym_verify(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        th_curr_data, th_curr_data_size, sign_data, sign_data_size);
#else
    result = spdm_asym_verify_hash(
        spdm_context->connection_info.version, SPDM_KEY_EXCHANGE_RSP,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        hash_data, hash_size, sign_data, sign_data_size);
#endif
    spdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
               context);
    if (!result) {
        DEBUG((DEBUG_INFO,
               "!!! verify_key_exchange_signature - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_key_exchange_signature - PASS !!!\n"));

    return TRUE;
}

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_key_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
                      IN spdm_session_info_t *session_info,
                      IN void *hmac_data,
                      IN uintn hmac_data_size)
{
    uintn hash_size;
    uint8_t calc_hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    ASSERT(hash_size == hmac_data_size);

    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, TRUE, &hash_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(calc_hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        DEBUG((DEBUG_INFO,
               "!!! verify_key_exchange_hmac - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_key_exchange_hmac - PASS !!!\n"));

    return TRUE;
}

/**
  This function generates the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
boolean spdm_generate_finish_req_signature(IN spdm_context_t *spdm_context,
                       IN spdm_session_info_t *session_info,
                       OUT uint8_t *signature)
{
    uint8_t hash_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    boolean result;
    uintn signature_size;
    uintn hash_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    signature_size = spdm_get_req_asym_signature_size(
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    result = libspdm_get_local_cert_chain_buffer(spdm_context,
                        (void **)&mut_cert_chain_buffer,
                        &mut_cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    // Debug code only - required for debug print of th_curr below
    DEBUG_CODE(
        if (!spdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
            return FALSE;
        }
    );
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hash - "));
    internal_dump_data(hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = spdm_requester_data_sign(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        FALSE, th_curr_data, th_curr_data_size, signature, &signature_size);
#else
    result = spdm_requester_data_sign(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        TRUE, hash_data, hash_size, signature, &signature_size);
#endif
    if (result) {
        DEBUG((DEBUG_INFO, "signature - "));
        internal_dump_data(signature, signature_size);
        DEBUG((DEBUG_INFO, "\n"));
    }

    return result;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_req_hmac(IN spdm_context_t *spdm_context,
                      IN spdm_session_info_t *session_info,
                      OUT void *hmac)
{
    uintn hash_size;
    uint8_t calc_hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return FALSE;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(calc_hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    copy_mem(hmac, calc_hmac_data, hash_size);

    return TRUE;
}

/**
  This function verifies the finish signature based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  sign_data                     The signature data buffer.
  @param  sign_data_size                 size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
boolean spdm_verify_finish_req_signature(IN spdm_context_t *spdm_context,
                     IN spdm_session_info_t *session_info,
                     IN void *sign_data,
                     IN intn sign_data_size)
{
    uintn hash_size;
    uint8_t hash_data[MAX_HASH_SIZE];
    boolean result;
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_data;
    uintn mut_cert_chain_data_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    uint8_t *mut_cert_buffer;
    uintn mut_cert_buffer_size;
    void *context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    result = libspdm_get_peer_cert_chain_buffer(spdm_context,
                           (void **)&mut_cert_chain_buffer,
                           &mut_cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    // Debug code only - required for debug print of th_curr below
    DEBUG_CODE(
        if (!spdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
            return FALSE;
        }
    );
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hash - "));
    internal_dump_data(hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    DEBUG((DEBUG_INFO, "signature - "));
    internal_dump_data(sign_data, sign_data_size);
    DEBUG((DEBUG_INFO, "\n"));

    //
    // Get leaf cert from cert chain
    //
    result = libspdm_get_peer_cert_chain_data(spdm_context,
                           (void **)&mut_cert_chain_data,
                           &mut_cert_chain_data_size);
    if (!result) {
        return FALSE;
    }
    result = x509_get_cert_from_cert_chain(mut_cert_chain_data,
                           mut_cert_chain_data_size, -1,
                           &mut_cert_buffer,
                           &mut_cert_buffer_size);
    if (!result) {
        return FALSE;
    }

    result = spdm_req_asym_get_public_key_from_x509(
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        mut_cert_buffer, mut_cert_buffer_size, &context);
    if (!result) {
        return FALSE;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = spdm_req_asym_verify(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        th_curr_data, th_curr_data_size, sign_data, sign_data_size);
#else
    result = spdm_req_asym_verify_hash(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        hash_data, hash_size, sign_data, sign_data_size);
#endif
    spdm_req_asym_free(
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        context);
    if (!result) {
        DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

    return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_req_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    IN uint8_t *hmac, IN uintn hmac_size)
{
    uint8_t hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    uintn hash_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    ASSERT(hmac_size == hash_size);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_peer_cert_chain_buffer(
            spdm_context, (void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return FALSE;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    if (const_compare_mem(hmac, hmac_data, hash_size) != 0) {
        DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_finish_req_hmac - PASS !!!\n"));
    return TRUE;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
boolean spdm_generate_finish_rsp_hmac(IN spdm_context_t *spdm_context,
                      IN spdm_session_info_t *session_info,
                      OUT uint8_t *hmac)
{
    uint8_t hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    uintn hash_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_get_local_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_peer_cert_chain_buffer(
            spdm_context, (void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return FALSE;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_rsp(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    copy_mem(hmac, hmac_data, hash_size);

    return TRUE;
}

/**
  This function verifies the finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_finish_rsp_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    IN void *hmac_data, IN uintn hmac_data_size)
{
    uintn hash_size;
    uint8_t calc_hmac_data[MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    ASSERT(hash_size == hmac_data_size);

    result = libspdm_get_peer_cert_chain_buffer(
        spdm_context, (void **)&cert_chain_buffer, &cert_chain_buffer_size);
    if (!result) {
        return FALSE;
    }

    if (session_info->mut_auth_requested) {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (void **)&mut_cert_chain_buffer,
            &mut_cert_chain_buffer_size);
        if (!result) {
            return FALSE;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_rsp(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(calc_hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_finish_rsp_hmac - PASS !!!\n"));

    return TRUE;
}

/**
  This function generates the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    OUT uint8_t *hmac)
{
    uint8_t hmac_data[MAX_HASH_SIZE];
    uintn hash_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(spdm_context, session_info,
                        NULL, 0, &th_curr_data_size,
                        th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, FALSE, &hash_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    copy_mem(hmac, hmac_data, hash_size);

    return TRUE;
}

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_exchange_rsp_hmac(IN spdm_context_t *spdm_context,
                      IN spdm_session_info_t *session_info,
                      IN void *hmac_data,
                      IN uintn hmac_data_size)
{
    uintn hash_size;
    uint8_t calc_hmac_data[MAX_HASH_SIZE];
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    ASSERT(hash_size == hmac_data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(spdm_context, session_info,
                        NULL, 0, &th_curr_data_size,
                        th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_exchange_rsp(
        spdm_context, session_info, TRUE, &hash_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(calc_hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    if (const_compare_mem(calc_hmac_data, hmac_data, hash_size) != 0) {
        DEBUG((DEBUG_INFO,
               "!!! verify_psk_exchange_rsp_hmac - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_psk_exchange_rsp_hmac - PASS !!!\n"));

    return TRUE;
}

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
boolean
spdm_generate_psk_exchange_req_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    OUT void *hmac)
{
    uintn hash_size;
    uint8_t calc_hmac_data[MAX_HASH_SIZE];
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(spdm_context, session_info, NULL,
                          0, NULL, 0, &th_curr_data_size,
                          th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th_curr hmac - "));
    internal_dump_data(calc_hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    copy_mem(hmac, calc_hmac_data, hash_size);

    return TRUE;
}

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The session info of an SPDM session.
  @param  hmac_data                     The HMAC data buffer.
  @param  hmac_data_size                 size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
boolean spdm_verify_psk_finish_req_hmac(IN spdm_context_t *spdm_context,
                    IN spdm_session_info_t *session_info,
                    IN uint8_t *hmac, IN uintn hmac_size)
{
    uint8_t hmac_data[MAX_HASH_SIZE];
    uintn hash_size;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    ASSERT(hmac_size == hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(spdm_context, session_info, NULL,
                          0, NULL, 0, &th_curr_data_size,
                          th_curr_data);
    if (!result) {
        return FALSE;
    }

    result = spdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, th_curr_data,
        th_curr_data_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "Calc th_curr hmac - "));
    internal_dump_data(hmac_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    if (const_compare_mem(hmac, hmac_data, hash_size) != 0) {
        DEBUG((DEBUG_INFO,
               "!!! verify_psk_finish_req_hmac - FAIL !!!\n"));
        return FALSE;
    }
    DEBUG((DEBUG_INFO, "!!! verify_psk_finish_req_hmac - PASS !!!\n"));
    return TRUE;
}

/*
  This function calculates th1 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th1 hash

  @retval RETURN_SUCCESS  th1 hash is calculated.
*/
return_status libspdm_calculate_th1_hash(IN void *context,
                      IN void *spdm_session_info,
                      IN boolean is_requester,
                      OUT uint8_t *th1_hash_data)
{
    spdm_context_t *spdm_context;
    uintn hash_size;
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    spdm_session_info_t *session_info;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    spdm_context = context;

    DEBUG((DEBUG_INFO, "Calc th1 hash ...\n"));

    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (!session_info->use_psk) {
        if (is_requester) {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        } else {
            result = libspdm_get_local_cert_chain_buffer(
                spdm_context, (void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        }
        if (!result) {
            return RETURN_UNSUPPORTED;
        }
    } else {
        cert_chain_buffer = NULL;
        cert_chain_buffer_size = 0;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_exchange(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return RETURN_SECURITY_VIOLATION;
    }

    result = spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
              th_curr_data, th_curr_data_size, th1_hash_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hash_for_exchange(
        spdm_context, session_info, &hash_size, th1_hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th1 hash - "));
    internal_dump_data(th1_hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    return RETURN_SUCCESS;
}

/*
  This function calculates th2 hash.

  @param  spdm_context                  A pointer to the SPDM context.
  @param  session_info                  The SPDM session ID.
  @param  is_requester                  Indicate of the key generation for a requester or a responder.
  @param  th1_hash_data                  th2 hash

  @retval RETURN_SUCCESS  th2 hash is calculated.
*/
return_status libspdm_calculate_th2_hash(IN void *context,
                      IN void *spdm_session_info,
                      IN boolean is_requester,
                      OUT uint8_t *th2_hash_data)
{
    spdm_context_t *spdm_context;
    uintn hash_size;
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    uintn mut_cert_chain_buffer_size;
    spdm_session_info_t *session_info;
    boolean result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t th_curr_data[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    uintn th_curr_data_size;
#endif

    spdm_context = context;

    DEBUG((DEBUG_INFO, "Calc th2 hash ...\n"));

    session_info = spdm_session_info;

    hash_size = spdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (!session_info->use_psk) {
        if (is_requester) {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        } else {
            result = libspdm_get_local_cert_chain_buffer(
                spdm_context, (void **)&cert_chain_buffer,
                &cert_chain_buffer_size);
        }
        if (!result) {
            return RETURN_UNSUPPORTED;
        }
        if (session_info->mut_auth_requested) {
            if (is_requester) {
                result = libspdm_get_local_cert_chain_buffer(
                    spdm_context,
                    (void **)&mut_cert_chain_buffer,
                    &mut_cert_chain_buffer_size);
            } else {
                result = libspdm_get_peer_cert_chain_buffer(
                    spdm_context,
                    (void **)&mut_cert_chain_buffer,
                    &mut_cert_chain_buffer_size);
            }
            if (!result) {
                return RETURN_UNSUPPORTED;
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

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    th_curr_data_size = sizeof(th_curr_data);
    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr_data_size, th_curr_data);
    if (!result) {
        return RETURN_SECURITY_VIOLATION;
    }

    result = spdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
              th_curr_data, th_curr_data_size, th2_hash_data);
    if (!result) {
        return FALSE;
    }
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, th2_hash_data);
    if (!result) {
        return FALSE;
    }
#endif
    DEBUG((DEBUG_INFO, "th2 hash - "));
    internal_dump_data(th2_hash_data, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    return RETURN_SUCCESS;
}
