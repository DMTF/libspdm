/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_SETCERTLIB_H
#define RESPONDER_SETCERTLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * return if current code is running in a trusted environment.
 *
 * libspdm calls this function for each SET_CERTIFICATE request, but the result matters only for a
 * request that is not in a session and is for a slot other than 0, which libspdm refuses unless the
 * function returns true. Slot 0, and every slot within a session, can be set whatever it returns.
 *
 * @param[in]  spdm_context  A pointer to the SPDM context.
 * @param[in]  session_id    Indicates the session in which the request was received.
 *                           If NULL then the request was not received in a session.
 *
 * @retval  true   It is in a trusted environment.
 * @retval  false  It is not in a trusted environment.
 **/
extern bool libspdm_is_in_trusted_environment(void *spdm_context, const uint32_t *session_id);

/**
 * Get the size of storage space for a certificate chain in a specific slot.
 *
 * The size is in bytes. libspdm returns it when a GET_CERTIFICATE request sets SlotSizeRequested,
 * in the LargeRemainderLength field of a large CERTIFICATE response, or otherwise in the 16-bit
 * RemainderLength field, so a size above 0xFFFF is reported correctly only in a large response.
 *
 * @param[in]  spdm_context  A pointer to the SPDM context.
 * @param[in]  slot_id       The number of slot for the certificate chain.
 *
 * @return size of storage space for the certificate chain.
 **/
extern uint32_t libspdm_get_cert_chain_slot_storage_size(
    void *spdm_context,
    uint8_t slot_id);

/**
 * Refresh the spdm_context local certificate after a successful
 * SET_CERTIFICATE.
 *
 * After a successful SET_CERTIFICATE this callback is called.
 * The new and old certificates are supplied as arguments.
 *
 * This function should store the new certificate chain in
 * non-volatile memory.
 *
 * If cert_chain and cert_chain_size are NULL then the certificate chain in slot_id is erased, which
 * libspdm requests only for SPDM 1.3 and later. base_hash_algo, base_asym_algo, pqc_asym_algo and
 * hash_size are then 0. libspdm does not read *cert_chain_size back.
 *
 * If a reset isn't required, then it is the implementations
 * responsibility to allocate memory to store the new certificate
 * chain and update `LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN` to
 * use the new chain in libspdm.
 *
 * After which the old certificate chain can be freed. Unfortunately we can't
 * handle this in libspdm as it might require allocation, which is why the
 * HAL must handle this.
 *
 * For DEVICE_CERT and GENERIC_CERT this is a simple. All that needs to be done
 * is memory allocated, the new certificate copied and the old certificate freed.
 *
 * The ALIAS_CERT is similar, but required combining the new updated certificates
 * with the existing ones that aren't changed.
 *
 * @param[in,out]  spdm_context     A pointer to the SPDM context.
 * @param[in]      session_id       Indicates the session in which the request was received.
 *                                  If NULL then the request was not received in a session.
 * @param[in]      slot_id          The slot id of the certificate chain.
 * @param[in]      base_hash_algo   The negotiated base hash algorithm
 *                                  (SPDM_ALGORITHMS_BASE_HASH_ALGO_*). May be
 *                                  used by the HAL when (re)computing root
 *                                  certificate hashes or other digests.
 * @param[in]      base_asym_algo   Indicates the negotiated signing algorithms.
 * @param[in]      pqc_asym_algo    Indicates the negotiated PQC signing algorithms.
 * @param[in]      hash_size        Size in bytes of the negotiated base hash
 *                                  (used to locate the certificates inside the
 *                                  spdm_cert_chain_t buffer).
 * @param[in]      old_cert_chain   Pointer to the currently installed SPDM
 *                                  certificate chain (including the
 *                                  spdm_cert_chain_t header), or NULL if no
 *                                  chain has been installed yet.
 * @param[in]      old_cert_chain_size  Size in bytes of old_cert_chain. Must be
 *                                  zero when old_cert_chain is NULL.
 * @param[in]      cert_chain       The new SPDM certificate chain (including
 *                                  the spdm_cert_chain_t header and root hash).
 * @param[in,out]  cert_chain_size  Size of the new SPDM certificate chain, in
 *                                  bytes.
 * @param[in]      cert_model       The certificate model (one of
 *                                  SPDM_CERTIFICATE_INFO_CERT_MODEL_*) that
 *                                  applies to the certificate chain being
 *                                  written.
 * @param[in,out]  need_reset       On input, indicates the value of CERT_INSTALL_RESET_CAP.
 *                                  On output, indicates whether the device needs to be reset (true) for
 *                                  the SET_CERTIFICATE operation to complete.
 * @param[out]     is_busy          If true, indicates that the certificate chain cannot be written at
 *                                  this time, but it may be successful in a later call. The function's
 *                                  return value must be false if this parameter is true.
 *
 * @retval true   The certificate chain was successfully written to non-volatile memory.
 *                If a reset is required then the `need_reset` bool was set
 *                If a reset is not required the local certificate chain was
 *                successfully updated.
 * @retval false  Failed to update the local certificate chain or store the new chain.
 *                The new chain is not committed and not in use.
 **/
extern bool libspdm_update_local_cert_chain(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t slot_id,
    uint32_t base_hash_algo,
    uint32_t base_asym_algo,
    uint32_t pqc_asym_algo,
    size_t hash_size,
    const void *old_cert_chain,
    size_t old_cert_chain_size,
    const void *cert_chain,
    size_t *cert_chain_size,
    uint8_t cert_model,
    bool *need_reset,
    bool *is_busy);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#endif /* RESPONDER_SETCERTLIB_H */
