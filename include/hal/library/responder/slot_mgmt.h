/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_SLOT_MGMT_H
#define RESPONDER_SLOT_MGMT_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/* bank_id sentinel meaning "no Bank addressing". The legacy GET_CSR and SET_CERTIFICATE flows have
 * no Bank concept and pass this value; only the SLOT_MANAGEMENT GetCSR/SetCertificate SubCodes pass
 * a real BankID. BankID 0 is a valid Bank, so it cannot be used as the sentinel. Also defined in
 * csrlib.h / setcertlib.h (guarded by CSR_CAP / SET_CERT_CAP); defined here too so it is available
 * whenever SLOT_MANAGEMENT is compiled, independent of those capabilities. */
#ifndef LIBSPDM_SLOT_MANAGEMENT_BANK_ID_INVALID
#define LIBSPDM_SLOT_MANAGEMENT_BANK_ID_INVALID 0xFF
#endif

/**
 * read the SLOT_MANAGEMENT supported SubCodes bitmap.
 *
 * The Responder shall set a bit in the bit position of the SubCode value for every
 * SLOT_MANAGEMENT SubCode that the Responder supports. The bits corresponding to the
 * required SubCodes (SupportedSubCodes, GetBankInfo, GetBankDetails, GetCertificateChain)
 * shall always be set.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  sub_code_bitmap     A pointer to a 8-byte destination buffer to store the
 *                             supported SubCodes bitmap. The bit position corresponds to
 *                             the SubCode value.
 *
 * @retval true  get supported SubCodes successfully.
 * @retval false get supported SubCodes failed.
 **/
extern bool libspdm_read_slot_management_supported_subcodes(
    void *spdm_context,
    uint8_t *sub_code_bitmap);

/**
 * read the SLOT_MANAGEMENT GetBankInfo information.
 *
 * The BankElements are written directly into the response buffer (the destination is bounded
 * by the response buffer size, so there is no fixed maximum Bank count in the responder).
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  num_bank_elements   On input, the capacity, in BankElements, of the bank_elements
 *                             array. On output, the number of Banks reported.
 * @param  bank_elements       A pointer to a destination array to store the BankElements.
 *
 * @retval true  get bank info successfully.
 * @retval false get bank info failed (e.g. the destination is too small).
 **/
extern bool libspdm_read_slot_management_bank_info(
    void *spdm_context,
    uint8_t *num_bank_elements,
    spdm_slot_management_bank_element_struct_t *bank_elements);

/**
 * read the SLOT_MANAGEMENT GetBankDetails information for one Bank.
 *
 * Each slot's fixed fields are written into the slot_elements array (the on-wire SlotElement
 * structure). The element_length field is set by the Responder, not this hook. The digest of
 * each slot's certificate chain is returned separately, in slot_digests: slot N's digest is
 * stored at slot_digests + N * (*slot_digest_size). The digest is over the certificate chain
 * for the Bank's configured algorithm (the same chain that GetCertificateChain returns), using
 * the connection's negotiated hash algorithm; the chain need not be provisioned into the SPDM
 * context.
 *
 * @param  spdm_context                A pointer to the SPDM context.
 * @param  bank_id                     The Bank to retrieve details for.
 * @param  bank_attributes             The attributes of the Bank.
 * @param  asym_algo_capabilities      The asymmetric algorithms the Responder supports for this Bank.
 * @param  current_asym_algo           The currently configured asymmetric algorithm for this Bank.
 * @param  available_asym_algo         The currently available asymmetric algorithms for this Bank.
 * @param  pqc_asym_algo_capabilities  The PQC asymmetric algorithms the Responder supports for this Bank.
 * @param  current_pqc_asym_algo       The currently configured PQC asymmetric algorithm for this Bank.
 * @param  available_pqc_asym_algo     The currently available PQC asymmetric algorithms for this Bank.
 * @param  num_slot_elements           On input, the capacity of the slot_elements array.
 *                                     On output, the number of slots reported for this Bank.
 * @param  slot_elements               A pointer to a destination array to store the per-slot
 *                                     SlotElement structures (element_length is set by the
 *                                     Responder).
 * @param  slot_digest_size            On input, the stride, in bytes, of each digest in the
 *                                     slot_digests buffer (the negotiated hash size). On output,
 *                                     the size of each digest written.
 * @param  slot_digests                A pointer to a destination buffer to store the slots'
 *                                     certificate chain digests, one per slot at a stride of
 *                                     slot_digest_size.
 *
 * @retval true  get bank details successfully.
 * @retval false get bank details failed (e.g. unknown bank_id).
 **/
extern bool libspdm_read_slot_management_bank_details(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t *bank_attributes,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint32_t *available_asym_algo,
    uint32_t *pqc_asym_algo_capabilities,
    uint32_t *current_pqc_asym_algo,
    uint32_t *available_pqc_asym_algo,
    uint8_t *num_slot_elements,
    spdm_slot_management_slot_element_struct_t *slot_elements,
    uint32_t *slot_digest_size,
    uint8_t *slot_digests);

/**
 * read the certificate chain in a slot of a Bank (the SLOT_MANAGEMENT GetCertificateChain
 * SubCode).
 *
 * The certificate chain is not required to be provisioned into the SPDM context; the
 * Responder may manage it independently and return it through this hook.
 *
 * @param  spdm_context      A pointer to the SPDM context.
 * @param  bank_id           The Bank that contains the slot.
 * @param  slot_id           The slot to read the certificate chain from.
 * @param  cert_chain_size   On input, the capacity in bytes of the cert_chain buffer.
 *                           On output, the number of bytes written.
 * @param  cert_chain        A pointer to a destination buffer to store the certificate chain.
 *
 * @retval true  the certificate chain was read successfully.
 * @retval false read failed (e.g. unknown bank_id/slot_id, empty slot, buffer too small).
 **/
extern bool libspdm_read_slot_management_certificate_chain(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t slot_id,
    size_t *cert_chain_size,
    void *cert_chain);

/* Result of a ManageBank operation, returned in the bank_result out-parameter of
 * libspdm_write_slot_management_bank. The Responder maps these to the SLOT_MANAGEMENT_RESP or to
 * the spec-mandated ERROR codes for ManageBank. */
#define LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_OK 0
/* Generic rejection (e.g. unknown bank_id, unsupported algorithm) -> ERROR(InvalidRequest). */
#define LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_INVALID 1
/* A slot in the Bank already has a certificate provisioned -> ERROR(InvalidState). */
#define LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_INVALID_STATE 2
/* The Bank reconfiguration requires a device reset -> ERROR(ResetRequired). */
#define LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_RESET_REQUIRED 3

/**
 * configure the asymmetric algorithm of a Bank (the SLOT_MANAGEMENT ManageBank SubCode).
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  bank_id             The Bank to configure.
 * @param  operation           The Bank management operation (e.g. ConfigAlgo).
 * @param  select_asym_algo    The asymmetric algorithm to configure for the Bank.
 * @param  select_pqc_asym_algo  The PQC asymmetric algorithm to configure for the Bank.
 *                             At most one of select_asym_algo and select_pqc_asym_algo is set.
 * @param  bank_result         On output, one of LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_*. The
 *                             Responder uses this to select the response or the ERROR code
 *                             mandated by the specification (InvalidState when a slot in the Bank
 *                             is provisioned, ResetRequired when a reset is needed).
 *
 * @retval true  manage bank successfully (bank_result is *_OK).
 * @retval false manage bank failed; bank_result indicates which ERROR the Responder shall send.
 **/
extern bool libspdm_write_slot_management_bank(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t operation,
    uint32_t select_asym_algo,
    uint32_t select_pqc_asym_algo,
    uint8_t *bank_result);

/**
 * perform a management operation on a slot in a Bank (the SLOT_MANAGEMENT ManageSlot SubCode).
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  bank_id             The Bank that contains the slot.
 * @param  slot_id             The slot to operate on.
 * @param  operation           The slot management operation (e.g. Erase).
 * @param  need_reset          On input, whether the Responder advertises CERT_INSTALL_RESET_CAP.
 *                             On output, set to true if the device requires a reset to complete
 *                             the operation. Only honored by the Responder when
 *                             CERT_INSTALL_RESET_CAP is advertised.
 * @param  is_busy             On output, set to true if the device cannot perform the operation
 *                             at this time; the Responder shall return ErrorCode=Busy.
 *
 * @retval true  manage slot successfully.
 * @retval false manage slot failed (e.g. unknown bank_id/slot_id, unsupported operation, or busy).
 **/
extern bool libspdm_write_slot_management_slot(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t slot_id,
    uint8_t operation,
    bool *need_reset,
    bool *is_busy);

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */

#endif /* RESPONDER_SLOT_MANAGEMENT_H */
