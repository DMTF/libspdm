/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

/**
 * This function returns peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 *
 * @retval true  Peer certificate chain buffer including spdm_cert_chain_t header is returned.
 * @retval false Peer certificate chain buffer including spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_peer_cert_chain_buffer(IN void *context,
                                           OUT void **cert_chain_buffer,
                                           OUT uintn *cert_chain_buffer_size)
{
    spdm_context_t *spdm_context;

    spdm_context = context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    if (spdm_context->connection_info.peer_used_cert_chain_buffer_size !=
        0) {
        *cert_chain_buffer = spdm_context->connection_info
                             .peer_used_cert_chain_buffer;
        *cert_chain_buffer_size =
            spdm_context->connection_info
            .peer_used_cert_chain_buffer_size;
        return true;
    }
#endif
    if (spdm_context->local_context.peer_cert_chain_provision_size != 0) {
        *cert_chain_buffer =
            spdm_context->local_context.peer_cert_chain_provision;
        *cert_chain_buffer_size =
            spdm_context->local_context
            .peer_cert_chain_provision_size;
        return true;
    }
    return false;
}

/**
 * This function returns peer certificate chain data without spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size            size in bytes of the certitiface chain data.
 *
 * @retval true  Peer certificate chain data without spdm_cert_chain_t header is returned.
 * @retval false Peer certificate chain data without spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_peer_cert_chain_data(IN void *context,
                                         OUT void **cert_chain_data,
                                         OUT uintn *cert_chain_data_size)
{
    spdm_context_t *spdm_context;
    bool result;
    uintn hash_size;

    spdm_context = context;

    result = libspdm_get_peer_cert_chain_buffer(spdm_context, cert_chain_data,
                                                cert_chain_data_size);
    if (!result) {
        return false;
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    *cert_chain_data = (uint8_t *)*cert_chain_data +
                       sizeof(spdm_cert_chain_t) + hash_size;
    *cert_chain_data_size =
        *cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);
    return true;
}

/**
 * This function returns local used certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 *
 * @retval true  Local used certificate chain buffer including spdm_cert_chain_t header is returned.
 * @retval false Local used certificate chain buffer including spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_local_cert_chain_buffer(IN void *context,
                                            OUT void **cert_chain_buffer,
                                            OUT uintn *cert_chain_buffer_size)
{
    spdm_context_t *spdm_context;

    spdm_context = context;
    if (spdm_context->connection_info.local_used_cert_chain_buffer_size !=
        0) {
        *cert_chain_buffer = spdm_context->connection_info
                             .local_used_cert_chain_buffer;
        *cert_chain_buffer_size =
            spdm_context->connection_info
            .local_used_cert_chain_buffer_size;
        return true;
    }
    return false;
}

/**
 * This function returns local used certificate chain data without spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_data                Certitiface chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size            size in bytes of the certitiface chain data.
 *
 * @retval true  Local used certificate chain data without spdm_cert_chain_t header is returned.
 * @retval false Local used certificate chain data without spdm_cert_chain_t header is not found.
 **/
bool libspdm_get_local_cert_chain_data(IN void *context,
                                          OUT void **cert_chain_data,
                                          OUT uintn *cert_chain_data_size)
{
    spdm_context_t *spdm_context;
    bool result;
    uintn hash_size;

    spdm_context = context;

    result = libspdm_get_local_cert_chain_buffer(spdm_context, cert_chain_data,
                                                 cert_chain_data_size);
    if (!result) {
        return false;
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    *cert_chain_data = (uint8_t *)*cert_chain_data +
                       sizeof(spdm_cert_chain_t) + hash_size;
    *cert_chain_data_size =
        *cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);
    return true;
}

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates m1m2.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_mut                        Indicate if this is from mutual authentication.
 * @param  m1m2_buffer_size               size in bytes of the m1m2
 * @param  m1m2_buffer                   The buffer to store the m1m2
 *
 * @retval RETURN_SUCCESS  m1m2 is calculated.
 */
bool spdm_calculate_m1m2(IN void *context, IN bool is_mut,
                            IN OUT uintn *m1m2_buffer_size,
                            OUT void *m1m2_buffer)
{
    spdm_context_t *spdm_context;
    return_status status;
    uint32_t hash_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t m1m2;

    spdm_context = context;

    init_managed_buffer(&m1m2, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (is_mut) {
        DEBUG((DEBUG_INFO, "message_mut_b data :\n"));
        internal_dump_hex(
            get_managed_buffer(
                &spdm_context->transcript.message_mut_b),
            get_managed_buffer_size(
                &spdm_context->transcript.message_mut_b));
        status = append_managed_buffer(
            &m1m2,
            get_managed_buffer(
                &spdm_context->transcript.message_mut_b),
            get_managed_buffer_size(
                &spdm_context->transcript.message_mut_b));
        if (RETURN_ERROR(status)) {
            return false;
        }

        DEBUG((DEBUG_INFO, "message_mut_c data :\n"));
        internal_dump_hex(
            get_managed_buffer(
                &spdm_context->transcript.message_mut_c),
            get_managed_buffer_size(
                &spdm_context->transcript.message_mut_c));
        status = append_managed_buffer(
            &m1m2,
            get_managed_buffer(
                &spdm_context->transcript.message_mut_c),
            get_managed_buffer_size(
                &spdm_context->transcript.message_mut_c));
        if (RETURN_ERROR(status)) {
            return false;
        }

        /* Debug code only - calculate and print value of m1m2 mut hash*/
        DEBUG_CODE(
            if (!libspdm_hash_all(
                    spdm_context->connection_info.algorithm.base_hash_algo,
                    get_managed_buffer(&m1m2),
                    get_managed_buffer_size(&m1m2), hash_data)) {
            return false;
        }
            DEBUG((DEBUG_INFO, "m1m2 Mut hash - "));
            internal_dump_data(hash_data, hash_size);
            DEBUG((DEBUG_INFO, "\n"));
            );

    } else {
        DEBUG((DEBUG_INFO, "message_a data :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_context->transcript.message_a),
            get_managed_buffer_size(
                &spdm_context->transcript.message_a));
        status = append_managed_buffer(
            &m1m2,
            get_managed_buffer(&spdm_context->transcript.message_a),
            get_managed_buffer_size(
                &spdm_context->transcript.message_a));
        if (RETURN_ERROR(status)) {
            return false;
        }

        DEBUG((DEBUG_INFO, "message_b data :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_context->transcript.message_b),
            get_managed_buffer_size(
                &spdm_context->transcript.message_b));
        status = append_managed_buffer(
            &m1m2,
            get_managed_buffer(&spdm_context->transcript.message_b),
            get_managed_buffer_size(
                &spdm_context->transcript.message_b));
        if (RETURN_ERROR(status)) {
            return false;
        }

        DEBUG((DEBUG_INFO, "message_c data :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_context->transcript.message_c),
            get_managed_buffer_size(
                &spdm_context->transcript.message_c));
        status = append_managed_buffer(
            &m1m2,
            get_managed_buffer(&spdm_context->transcript.message_c),
            get_managed_buffer_size(
                &spdm_context->transcript.message_c));
        if (RETURN_ERROR(status)) {
            return false;
        }

        /* Debug code only - calculate and print value of m1m2 hash*/
        DEBUG_CODE(
            if (!libspdm_hash_all(
                    spdm_context->connection_info.algorithm.base_hash_algo,
                    get_managed_buffer(&m1m2),
                    get_managed_buffer_size(&m1m2), hash_data)) {
            return false;
        }
            DEBUG((DEBUG_INFO, "m1m2 hash - "));
            internal_dump_data(hash_data, hash_size);
            DEBUG((DEBUG_INFO, "\n"));
            );
    }

    *m1m2_buffer_size = get_managed_buffer_size(&m1m2);
    copy_mem(m1m2_buffer, get_managed_buffer(&m1m2), *m1m2_buffer_size);

    return true;
}
#else
/*
 * This function calculates m1m2 hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_mut                        Indicate if this is from mutual authentication.
 * @param  m1m2_hash_size               size in bytes of the m1m2 hash
 * @param  m1m2_hash                   The buffer to store the m1m2 hash
 *
 * @retval RETURN_SUCCESS  m1m2 is calculated.
 */
bool spdm_calculate_m1m2_hash(IN void *context, IN bool is_mut,
                                 IN OUT uintn *m1m2_hash_size,
                                 OUT void *m1m2_hash)
{
    spdm_context_t *spdm_context;
    uint32_t hash_size;
    bool result;

    spdm_context = context;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (is_mut) {
        result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                     spdm_context->transcript.digest_context_mut_m1m2, m1m2_hash);
        if (!result) {
            return false;
        }
        DEBUG((DEBUG_INFO, "m1m2 Mut hash - "));
        internal_dump_data(m1m2_hash, hash_size);
        DEBUG((DEBUG_INFO, "\n"));

    } else {
        result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                     spdm_context->transcript.digest_context_m1m2, m1m2_hash);
        if (!result) {
            return false;
        }
        DEBUG((DEBUG_INFO, "m1m2 hash - "));
        internal_dump_data(m1m2_hash, hash_size);
        DEBUG((DEBUG_INFO, "\n"));
    }

    *m1m2_hash_size = hash_size;

    return true;
}
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
/*
 * This function calculates l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  l1l2_buffer_size               size in bytes of the l1l2
 * @param  l1l2_buffer                   The buffer to store the l1l2
 *
 * @retval RETURN_SUCCESS  l1l2 is calculated.
 */
bool spdm_calculate_l1l2(IN void *context, IN void *session_info,
                            IN OUT uintn *l1l2_buffer_size, OUT void *l1l2_buffer)
{
    spdm_context_t *spdm_context;
    return_status status;
    spdm_session_info_t *spdm_session_info;
    uint32_t hash_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    large_managed_buffer_t l1l2;

    spdm_context = context;
    spdm_session_info = session_info;

    init_managed_buffer(&l1l2, LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if ((spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >
        SPDM_MESSAGE_VERSION_11) {

        /* Need append VCA since 1.2 script*/

        DEBUG((DEBUG_INFO, "message_a data :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_context->transcript.message_a),
            get_managed_buffer_size(
                &spdm_context->transcript.message_a));
        status = append_managed_buffer(
            &l1l2,
            get_managed_buffer(&spdm_context->transcript.message_a),
            get_managed_buffer_size(
                &spdm_context->transcript.message_a));
        if (RETURN_ERROR(status)) {
            return false;
        }
    }

    if (spdm_session_info == NULL) {
        DEBUG((DEBUG_INFO, "message_m data :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_context->transcript.message_m),
            get_managed_buffer_size(&spdm_context->transcript.message_m));
        status = append_managed_buffer(
            &l1l2,
            get_managed_buffer(&spdm_context->transcript.message_m),
            get_managed_buffer_size(
                &spdm_context->transcript.message_m));
    } else {
        DEBUG((DEBUG_INFO, "use message_m in session :\n"));
        internal_dump_hex(
            get_managed_buffer(&spdm_session_info->session_transcript.message_m),
            get_managed_buffer_size(&spdm_session_info->session_transcript.message_m));
        status = append_managed_buffer(
            &l1l2,
            get_managed_buffer(&spdm_session_info->session_transcript.message_m),
            get_managed_buffer_size(
                &spdm_session_info->session_transcript.message_m));
    }
    if (RETURN_ERROR(status)) {
        return false;
    }

    DEBUG((DEBUG_INFO, "message_m data :\n"));
    internal_dump_hex(l1l2_buffer, *l1l2_buffer_size);

    /* Debug code only - calculate and print value of l1l2 hash*/
    DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                get_managed_buffer(&l1l2),
                get_managed_buffer_size(&l1l2), hash_data)) {
        return false;
    }
        DEBUG((DEBUG_INFO, "l1l2 hash - "));
        internal_dump_data(hash_data, hash_size);
        DEBUG((DEBUG_INFO, "\n"));
        );

    *l1l2_buffer_size = get_managed_buffer_size(&l1l2);
    copy_mem(l1l2_buffer, get_managed_buffer(&l1l2), *l1l2_buffer_size);

    return true;
}
#else
/*
 * This function calculates l1l2 hash.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  l1l2_hash_size               size in bytes of the l1l2 hash
 * @param  l1l2_hash                   The buffer to store the l1l2 hash
 *
 * @retval RETURN_SUCCESS  l1l2 is calculated.
 */
bool spdm_calculate_l1l2_hash(IN void *context, IN void *session_info,
                                 IN OUT uintn *l1l2_hash_size, OUT void *l1l2_hash)
{
    spdm_context_t *spdm_context;
    spdm_session_info_t *spdm_session_info;
    bool result;

    uint32_t hash_size;

    spdm_context = context;
    spdm_session_info = session_info;

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if (spdm_session_info == NULL) {
        result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                     spdm_context->transcript.digest_context_l1l2, l1l2_hash);
    } else {
        DEBUG((DEBUG_INFO, "use message_m in session :\n"));
        result = libspdm_hash_final (spdm_context->connection_info.algorithm.base_hash_algo,
                                     spdm_session_info->session_transcript.digest_context_l1l2,
                                     l1l2_hash);
    }
    if (!result) {
        return false;
    }
    DEBUG((DEBUG_INFO, "l1l2 hash - "));
    internal_dump_data(l1l2_hash, hash_size);
    DEBUG((DEBUG_INFO, "\n"));

    *l1l2_hash_size = hash_size;

    return true;
}
#endif

/**
 * This function generates the certificate chain hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  slot_id                    The slot index of the certificate chain.
 * @param  signature                    The buffer to store the certificate chain hash.
 *
 * @retval true  certificate chain hash is generated.
 * @retval false certificate chain hash is not generated.
 **/
bool spdm_generate_cert_chain_hash(IN spdm_context_t *spdm_context,
                                      IN uintn slot_id, OUT uint8_t *hash)
{
    ASSERT(slot_id < spdm_context->local_context.slot_count);
    return libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->local_context.local_cert_chain_provision[slot_id],
        spdm_context->local_context
        .local_cert_chain_provision_size[slot_id],
        hash);
}

/**
 * This function verifies the digest.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  digest                       The digest data buffer.
 * @param  digest_count                   size of the digest data buffer.
 *
 * @retval true  digest verification pass.
 * @retval false digest verification fail.
 **/
bool spdm_verify_peer_digests(IN spdm_context_t *spdm_context,
                                 IN void *digest, IN uintn digest_count)
{
    uintn hash_size;
    uint8_t *hash_buffer;
    uint8_t cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    uintn index;
    bool result;

    cert_chain_buffer =
        spdm_context->local_context.peer_cert_chain_provision;
    cert_chain_buffer_size =
        spdm_context->local_context.peer_cert_chain_provision_size;
    if ((cert_chain_buffer != NULL) && (cert_chain_buffer_size != 0)) {
        hash_size = libspdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);
        hash_buffer = digest;

        result = libspdm_hash_all(
            spdm_context->connection_info.algorithm.base_hash_algo,
            cert_chain_buffer, cert_chain_buffer_size,
            cert_chain_buffer_hash);
        if (!result) {
            DEBUG((DEBUG_INFO, "!!! verify_peer_digests - FAIL (hash calculation) !!!\n"));
            return false;
        }

        for (index = 0; index < digest_count; index++)
        {
            if (const_compare_mem(hash_buffer, cert_chain_buffer_hash, hash_size) == 0) {
                DEBUG((DEBUG_INFO, "!!! verify_peer_digests - PASS !!!\n"));
                return true;
            }
            hash_buffer += hash_size;
        }

        DEBUG((DEBUG_INFO,
               "!!! verify_peer_digests - FAIL !!!\n"));
        return false;
    } else {
        DEBUG((DEBUG_INFO, "!!! verify_peer_digests - PASS !!!\n"));
    }
    return true;
}

/**
 * This function verifies peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  cert_chain_buffer              Certitiface chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size          size in bytes of the certitiface chain buffer.
 * @param  trust_anchor                  A buffer to hold the trust_anchor which is used to validate the peer certificate, if not NULL.
 * @param  trust_anchor_size             A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval true  Peer certificate chain buffer verification passed.
 * @retval false Peer certificate chain buffer verification failed.
 **/
bool spdm_verify_peer_cert_chain_buffer(IN spdm_context_t *spdm_context,
                                           IN void *cert_chain_buffer,
                                           IN uintn cert_chain_buffer_size,
                                           OUT void **trust_anchor OPTIONAL,
                                           OUT uintn *trust_anchor_size OPTIONAL)
{
    uint8_t *cert_chain_data;
    uintn cert_chain_data_size;
    uint8_t *root_cert;
    uintn root_cert_size;
    uint8_t root_cert_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn root_cert_hash_size;
    uint8_t *received_root_cert;
    uintn received_root_cert_size;
    bool result;
    uint8_t root_cert_index;

    result = libspdm_verify_certificate_chain_buffer(
        spdm_context->connection_info.algorithm.base_hash_algo,
        cert_chain_buffer, cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    root_cert_index = 0;
    root_cert = spdm_context->local_context.peer_root_cert_provision[root_cert_index];
    root_cert_size =
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index];
    cert_chain_data = spdm_context->local_context.peer_cert_chain_provision;
    cert_chain_data_size =
        spdm_context->local_context.peer_cert_chain_provision_size;

    root_cert_hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    if ((root_cert != NULL) && (root_cert_size != 0)) {
        while ((root_cert != NULL) && (root_cert_size != 0)) {
            result = libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                root_cert, root_cert_size, root_cert_hash);
            if (!result) {
                DEBUG((DEBUG_INFO,
                       "!!! verify_peer_cert_chain_buffer - FAIL (hash calculation) !!!\n"));
                return false;
            }

            if (const_compare_mem((uint8_t *)cert_chain_buffer + sizeof(spdm_cert_chain_t),
                                  root_cert_hash, root_cert_hash_size) == 0) {
                break;
            } else if ((root_cert_index < (LIBSPDM_MAX_ROOT_CERT_SUPPORT - 1)) &&
                       (spdm_context->local_context.peer_root_cert_provision[root_cert_index + 1] !=
                        NULL)) {
                root_cert_index++;
                root_cert = spdm_context->local_context.peer_root_cert_provision[root_cert_index];
                root_cert_size =
                    spdm_context->local_context.peer_root_cert_provision_size[root_cert_index];
            } else {
                DEBUG((DEBUG_INFO,
                       "!!! verify_peer_cert_chain_buffer - FAIL (all root cert hash mismatch) !!!\n"));
                return false;
            }
        }

        result = x509_get_cert_from_cert_chain(
            (uint8_t *)cert_chain_buffer + sizeof(spdm_cert_chain_t) + root_cert_hash_size,
            cert_chain_buffer_size - sizeof(spdm_cert_chain_t) - root_cert_hash_size,
            0, &received_root_cert, &received_root_cert_size);
        if (!result) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_peer_cert_chain_buffer - FAIL (cert retrieval fail) !!!\n"));
            return false;
        }
        if (libspdm_is_root_certificate(received_root_cert, received_root_cert_size)) {
            if (const_compare_mem(received_root_cert, root_cert, root_cert_size) != 0) {
                DEBUG((DEBUG_INFO,
                       "!!! verify_peer_cert_chain_buffer - FAIL (root cert mismatch) !!!\n"));
                return false;
            }
        } else {
            if (!x509_verify_cert(received_root_cert, received_root_cert_size,
                                  root_cert, root_cert_size)) {
                DEBUG((DEBUG_INFO,
                       "!!! verify_peer_cert_chain_buffer - FAIL (received root cert verify failed)!!!\n"));
                return false;
            }
        }
        if (trust_anchor != NULL) {
            *trust_anchor = root_cert;
        }
        if (trust_anchor_size != NULL) {
            *trust_anchor_size = root_cert_size;
        }
    } else if ((cert_chain_data != NULL) && (cert_chain_data_size != 0)) {
        /* Whether it contains the root certificate or not,
         * it should be equal to the one provisioned in trusted environment*/
        if (cert_chain_data_size != cert_chain_buffer_size) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_peer_cert_chain_buffer - FAIL !!!\n"));
            return false;
        }
        if (const_compare_mem(cert_chain_buffer, cert_chain_data,
                              cert_chain_buffer_size) != 0) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_peer_cert_chain_buffer - FAIL !!!\n"));
            return false;
        }
        if (trust_anchor != NULL) {
            *trust_anchor = cert_chain_data + sizeof(spdm_cert_chain_t) +
                            libspdm_get_hash_size(
                spdm_context->connection_info.algorithm.base_hash_algo);
        }
        if (trust_anchor_size != NULL) {
            *trust_anchor_size = cert_chain_data_size;
        }
    }
    /*
     * When there is no root_cert and cert_chain_data in local_context, the return is true too.
     * No provision means the caller wants to verify the trust anchor of the cert chain.
     */
    DEBUG((DEBUG_INFO, "!!! verify_peer_cert_chain_buffer - PASS !!!\n"));

    return true;
}

/**
 * This function generates the challenge signature based upon m1m2 for authentication.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Indicate of the signature generation for a requester or a responder.
 * @param  signature                    The buffer to store the challenge signature.
 *
 * @retval true  challenge signature is generated.
 * @retval false challenge signature is not generated.
 **/
bool spdm_generate_challenge_auth_signature(IN spdm_context_t *spdm_context,
                                               IN bool is_requester,
                                               OUT uint8_t *signature)
{
    bool result;
    uintn signature_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t m1m2_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn m1m2_buffer_size;
#else
    uint8_t m1m2_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn m1m2_hash_size;
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    m1m2_buffer_size = sizeof(m1m2_buffer);
    result = spdm_calculate_m1m2(spdm_context, is_requester,
                                 &m1m2_buffer_size, &m1m2_buffer);
#else
    m1m2_hash_size = sizeof(m1m2_hash);
    result = spdm_calculate_m1m2_hash(spdm_context, is_requester,
                                      &m1m2_hash_size, &m1m2_hash);
#endif
    if (!result) {
        return false;
    }

    if (is_requester) {
        signature_size = libspdm_get_req_asym_signature_size(
            spdm_context->connection_info.algorithm
            .req_base_asym_alg);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        result = libspdm_requester_data_sign(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo,
            false, m1m2_buffer, m1m2_buffer_size, signature,
            &signature_size);
#else
        result = libspdm_requester_data_sign(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo,
            true, m1m2_hash, m1m2_hash_size, signature,
            &signature_size);
#endif
    } else {
        signature_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        result = libspdm_responder_data_sign(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            false, m1m2_buffer, m1m2_buffer_size, signature,
            &signature_size);
#else
        result = libspdm_responder_data_sign(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            true, m1m2_hash, m1m2_hash_size, signature,
            &signature_size);
#endif
    }

    return result;
}

/**
 * This function verifies the certificate chain hash.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  certificate_chain_hash         The certificate chain hash data buffer.
 * @param  certificate_chain_hash_size     size in bytes of the certificate chain hash data buffer.
 *
 * @retval true  hash verification pass.
 * @retval false hash verification fail.
 **/
bool spdm_verify_certificate_chain_hash(IN spdm_context_t *spdm_context,
                                           IN void *certificate_chain_hash,
                                           IN uintn certificate_chain_hash_size)
{
    uintn hash_size;
    uint8_t cert_chain_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *cert_chain_buffer;
    uintn cert_chain_buffer_size;
    bool result;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_buffer(spdm_context,
                                                (void **)&cert_chain_buffer,
                                                &cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    result = libspdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
                              cert_chain_buffer, cert_chain_buffer_size,
                              cert_chain_buffer_hash);
    if (!result) {
        DEBUG((DEBUG_INFO,
               "!!! verify_certificate_chain_hash - FAIL (hash calculation) !!!\n"));
        return false;
    }

    if (hash_size != certificate_chain_hash_size) {
        DEBUG((DEBUG_INFO,
               "!!! verify_certificate_chain_hash - FAIL !!!\n"));
        return false;
    }
    if (const_compare_mem(certificate_chain_hash, cert_chain_buffer_hash,
                          certificate_chain_hash_size) != 0) {
        DEBUG((DEBUG_INFO,
               "!!! verify_certificate_chain_hash - FAIL !!!\n"));
        return false;
    }
#else
    if (spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size != 0) {
        if (spdm_context->connection_info.peer_used_cert_chain_buffer_hash_size !=
            certificate_chain_hash_size) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_certificate_chain_hash - FAIL !!!\n"));
            return false;
        }

        if (const_compare_mem(certificate_chain_hash,
                              spdm_context->connection_info.peer_used_cert_chain_buffer_hash,
                              certificate_chain_hash_size) != 0) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_certificate_chain_hash - FAIL !!!\n"));
            return false;
        }

    } else {
        result = libspdm_get_peer_cert_chain_buffer(spdm_context,
                                                    (void **)&cert_chain_buffer,
                                                    &cert_chain_buffer_size);
        if (!result) {
            return false;
        }

        hash_size = libspdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);

        result = libspdm_hash_all(spdm_context->connection_info.algorithm.base_hash_algo,
                                  cert_chain_buffer, cert_chain_buffer_size,
                                  cert_chain_buffer_hash);
        if (!result) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_certificate_chain_hash - FAIL (hash calculation) !!!\n"));
            return false;
        }

        if (hash_size != certificate_chain_hash_size) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_certificate_chain_hash - FAIL !!!\n"));
            return false;
        }
        if (const_compare_mem(certificate_chain_hash, cert_chain_buffer_hash,
                              certificate_chain_hash_size) != 0) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_certificate_chain_hash - FAIL !!!\n"));
            return false;
        }
    }
#endif
    DEBUG((DEBUG_INFO, "!!! verify_certificate_chain_hash - PASS !!!\n"));
    return true;
}

/**
 * This function verifies the challenge signature based upon m1m2.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Indicate of the signature verification for a requester or a responder.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool spdm_verify_challenge_auth_signature(IN spdm_context_t *spdm_context,
                                             IN bool is_requester,
                                             IN void *sign_data,
                                             IN uintn sign_data_size)
{
    bool result;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    void *context;
    uint8_t *cert_chain_data;
    uintn cert_chain_data_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t m1m2_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn m1m2_buffer_size;
#else
    uint8_t m1m2_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn m1m2_hash_size;
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    m1m2_buffer_size = sizeof(m1m2_buffer);
    result = spdm_calculate_m1m2(spdm_context, !is_requester,
                                 &m1m2_buffer_size, &m1m2_buffer);
#else
    m1m2_hash_size = sizeof(m1m2_hash);
    result = spdm_calculate_m1m2_hash(spdm_context, !is_requester,
                                      &m1m2_hash_size, &m1m2_hash);
#endif
    if (!result) {
        return false;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return false;
    }

    /* Get leaf cert from cert chain*/
    result = x509_get_cert_from_cert_chain(cert_chain_data,
                                           cert_chain_data_size, -1,
                                           &cert_buffer, &cert_buffer_size);
    if (!result) {
        return false;
    }

    if (is_requester) {
        result = libspdm_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm.base_asym_algo,
            cert_buffer, cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_asym_verify(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            context, m1m2_buffer, m1m2_buffer_size, sign_data,
            sign_data_size);
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            context);
    } else {
        result = libspdm_req_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            cert_buffer, cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_verify(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo,
            context, m1m2_buffer, m1m2_buffer_size, sign_data,
            sign_data_size);
        libspdm_req_asym_free(spdm_context->connection_info.algorithm
                              .req_base_asym_alg,
                              context);
    }
#else
    if (is_requester) {
        if (spdm_context->connection_info.peer_used_leaf_cert_public_key != NULL) {
            context = spdm_context->connection_info.peer_used_leaf_cert_public_key;
            result = libspdm_asym_verify_hash(
                spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
                spdm_context->connection_info.algorithm.base_asym_algo,
                spdm_context->connection_info.algorithm.base_hash_algo,
                context, m1m2_hash, m1m2_hash_size, sign_data,
                sign_data_size);
            if (!result) {
                DEBUG((DEBUG_INFO,
                       "!!! verify_challenge_signature - FAIL !!!\n"));
                return false;
            }
            return true;
        }

    } else {
        if (spdm_context->connection_info.peer_used_leaf_cert_public_key != NULL) {
            context = spdm_context->connection_info.peer_used_leaf_cert_public_key;
            result = libspdm_req_asym_verify_hash(
                spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
                spdm_context->connection_info.algorithm
                .req_base_asym_alg,
                spdm_context->connection_info.algorithm.base_hash_algo,
                context, m1m2_hash, m1m2_hash_size, sign_data,
                sign_data_size);
            if (!result) {
                DEBUG((DEBUG_INFO,
                       "!!! verify_challenge_signature - FAIL !!!\n"));
                return false;
            }
            return true;
        }
    }

    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return false;
    }


    /* Get leaf cert from cert chain*/

    result = x509_get_cert_from_cert_chain(cert_chain_data,
                                           cert_chain_data_size, -1,
                                           &cert_buffer, &cert_buffer_size);
    if (!result) {
        return false;
    }

    if (is_requester) {
        result = libspdm_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm.base_asym_algo,
            cert_buffer, cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            context, m1m2_hash, m1m2_hash_size, sign_data,
            sign_data_size);
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            context);
    } else {
        result = libspdm_req_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            cert_buffer, cert_buffer_size, &context);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_CHALLENGE_AUTH,
            spdm_context->connection_info.algorithm
            .req_base_asym_alg,
            spdm_context->connection_info.algorithm.base_hash_algo,
            context, m1m2_hash, m1m2_hash_size, sign_data,
            sign_data_size);
        libspdm_req_asym_free(spdm_context->connection_info.algorithm
                              .req_base_asym_alg,
                              context);
    }
#endif
    if (!result) {
        DEBUG((DEBUG_INFO,
               "!!! verify_challenge_signature - FAIL !!!\n"));
        return false;
    }

    DEBUG((DEBUG_INFO, "!!! verify_challenge_signature - PASS !!!\n"));

    return true;
}

/**
 * This function calculate the measurement summary hash size.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  is_requester                  Is the function called from a requester.
 * @param  measurement_summary_hash_type   The type of the measurement summary hash.
 *
 * @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
 * @return measurement summary hash size according to type.
 **/
uint32_t
spdm_get_measurement_summary_hash_size(IN spdm_context_t *spdm_context,
                                       IN bool is_requester,
                                       IN uint8_t measurement_summary_hash_type)
{
    if (!spdm_is_capabilities_flag_supported(
            spdm_context, is_requester, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        return 0;
    }

    switch (measurement_summary_hash_type) {
    case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        return 0;
        break;

    case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
        return libspdm_get_hash_size(
            spdm_context->connection_info.algorithm.base_hash_algo);
        break;
    default:
        return 0;
        break;
    }
}

/**
 * This function generates the measurement signature to response message based upon l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  signature                    The buffer to store the signature.
 *
 * @retval true  measurement signature is generated.
 * @retval false measurement signature is not generated.
 **/
bool spdm_generate_measurement_signature(IN spdm_context_t *spdm_context,
                                            IN spdm_session_info_t *session_info,
                                            OUT uint8_t *signature)
{
    uintn signature_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t l1l2_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn l1l2_buffer_size;
#else
    uint8_t l1l2_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn l1l2_hash_size;
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    l1l2_buffer_size = sizeof(l1l2_buffer);
    result = spdm_calculate_l1l2(spdm_context, session_info, &l1l2_buffer_size,
                                 l1l2_buffer);
#else
    l1l2_hash_size = sizeof(l1l2_hash);
    result = spdm_calculate_l1l2_hash(spdm_context, session_info, &l1l2_hash_size,
                                      l1l2_hash);
#endif
    if (!result) {
        return false;
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        false, l1l2_buffer, l1l2_buffer_size, signature, &signature_size);
#else
    result = libspdm_responder_data_sign(
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        true, l1l2_hash, l1l2_hash_size, signature, &signature_size);
#endif
    return result;
}

/**
 * This function verifies the measurement signature based upon l1l2.
 * If session_info is NULL, this function will use M cache of SPDM context,
 * else will use M cache of SPDM session context.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  A pointer to the SPDM session context.
 * @param  sign_data                     The signature data buffer.
 * @param  sign_data_size                 size in bytes of the signature data buffer.
 *
 * @retval true  signature verification pass.
 * @retval false signature verification fail.
 **/
bool spdm_verify_measurement_signature(IN spdm_context_t *spdm_context,
                                          IN spdm_session_info_t *session_info,
                                          IN void *sign_data,
                                          IN uintn sign_data_size)
{
    bool result;
    uint8_t *cert_buffer;
    uintn cert_buffer_size;
    void *context;
    uint8_t *cert_chain_data;
    uintn cert_chain_data_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t l1l2_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uintn l1l2_buffer_size;
#else
    uint8_t l1l2_hash[LIBSPDM_MAX_HASH_SIZE];
    uintn l1l2_hash_size;
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    l1l2_buffer_size = sizeof(l1l2_buffer);
    result = spdm_calculate_l1l2(spdm_context, session_info, &l1l2_buffer_size,
                                 l1l2_buffer);
#else
    l1l2_hash_size = sizeof(l1l2_hash);
    result = spdm_calculate_l1l2_hash(spdm_context, session_info, &l1l2_hash_size,
                                      l1l2_hash);
#endif
    if (!result) {
        return false;
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return false;
    }

    /* Get leaf cert from cert chain*/
    result = x509_get_cert_from_cert_chain(cert_chain_data,
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
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        l1l2_buffer, l1l2_buffer_size, sign_data, sign_data_size);
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      context);
#else
    if (spdm_context->connection_info.peer_used_leaf_cert_public_key != NULL) {
        result = libspdm_asym_verify_hash(
            spdm_context->connection_info.version, SPDM_MEASUREMENTS,
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.peer_used_leaf_cert_public_key,
            l1l2_hash, l1l2_hash_size, sign_data, sign_data_size);
        if (!result) {
            DEBUG((DEBUG_INFO,
                   "!!! verify_measurement_signature - FAIL !!!\n"));
            return false;
        }

        DEBUG((DEBUG_INFO, "!!! verify_measurement_signature - PASS !!!\n"));
        return true;
    }

    result = libspdm_get_peer_cert_chain_data(
        spdm_context, (void **)&cert_chain_data, &cert_chain_data_size);
    if (!result) {
        return false;
    }


    /* Get leaf cert from cert chain*/

    result = x509_get_cert_from_cert_chain(cert_chain_data,
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
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo, context,
        l1l2_hash, l1l2_hash_size, sign_data, sign_data_size);
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      context);
#endif
    if (!result) {
        DEBUG((DEBUG_INFO,
               "!!! verify_measurement_signature - FAIL !!!\n"));
        return false;
    }

    DEBUG((DEBUG_INFO, "!!! verify_measurement_signature - PASS !!!\n"));
    return true;
}
