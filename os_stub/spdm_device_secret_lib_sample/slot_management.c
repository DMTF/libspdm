/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/responder/slot_mgmt.h"
#include "slot_management_internal.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/* This sample models the SLOT_MANAGEMENT Banks per the specification's concepts:
 *
 *   - A Bank is a set of certificate slots that all use one asymmetric algorithm.
 *   - A Bank can contain multiple slots. Each slot has a SlotID in the range 0-7 that is the
 *     value carried on the wire (DSP0274 Table 152), not a packed index. A slot is associated
 *     with a key pair (KeyPairID).
 *   - SlotID is scoped within a Bank.
 *
 * The Banks are derived from the key pairs reported by GET_KEY_PAIR_INFO: the key pairs are
 * grouped by their currently configured asymmetric algorithm, one Bank per distinct algorithm.
 * The sample certificate store provides two certificate chains per algorithm
 * (bundle_responder.certchain.der for SlotID 0 and bundle_responder.certchain1.der for SlotID
 * 1), so each Bank exposes those two wire SlotIDs. Slot 0 records the KeyPairID of the Bank's
 * key pair; slot 1 shares the same key pair in this sample. This keeps the SLOT_MANAGEMENT
 * responses consistent with the certificate store while modeling SlotID as the true wire
 * value. */

/* Certificate slot states (DSP0274 "Certificate slots"). A slot is in exactly one of four states,
 * observable through the SupportedSlotMask/ProvisionedSlotMask and the BankDetails SlotElement
 * fields. This sample represents them as follows:
 *
 *   State                  Wire (masks / SlotElement)                    Sample representation
 *   ---------------------  --------------------------------------------  ----------------------------
 *   1. Does not exist      Not in SupportedSlotMask; no SlotElement      Slot absent from the Bank's
 *                          emitted for it.                               slots[] table.
 *   2. Exists and empty    Supported=1, Provisioned=0;                   Slot in slots[]; no cert
 *                          SlotAttributes.Provisioned=0,                 chain readable for the slot
 *                          CertificateInfo=0, digest all-zero.           (e.g. erased: zero-length
 *                                                                        NVM file).
 *   3. Exists with key     Supported=1, Provisioned=1,                   NOT currently reachable in
 *                          CertificateInfo=0 (key pair associated,       this sample. No cert-side
 *                          no certificate chain).                        operation produces a
 *                                                                        key-only slot (see below).
 *   4. Exists with key     Supported=1, Provisioned=1,                   Slot in slots[]; a cert
 *      and cert            CertificateInfo!=0; digest set.               chain is readable (NVM file
 *                                                                        or static bundle).
 *
 * Whether a slot is populated (state 4) or empty (state 2) is NOT cached in slots[]; it is derived
 * on demand from the certificate store, the same single source of truth the base SET_CERTIFICATE
 * flow uses (libspdm_write_certificate_to_nvm): a per-(Bank,slot) NVM file if present, else the
 * static bundle. A ManageSlot/SET_CERTIFICATE Erase writes a zero-length NVM file, which the read
 * path reports as empty (state 2) without falling back to the static bundle.
 *
 * State 3 ("Exists with key") is defined by the spec but is not reachable here: GenerateKeyPair
 * (SET_KEY_PAIR_INFO) requires a key pair with no associated certificate slot, and the cert-side
 * commands only move a slot between "has cert" (4) and "no cert" (2) without removing the key
 * (DSP0274 erase does not erase the key). Reaching state 3 would require an internal key-only
 * provisioning hook, which this sample does not wire up.
 *
 * Note: like the base SET_CERTIFICATE flow, this sample does not update the live
 * local_cert_chain_provision[] store on SET_CERTIFICATE/Erase; the model is write NVM -> reset ->
 * integrator reloads on next boot. Within a single boot a change to the in-use slot is only
 * observed after that reload. */

/* The number of wire SlotIDs each Bank exposes in this sample. The sample certificate store has
 * two chains per algorithm (SlotID 0 and SlotID 1). */
#define LIBSPDM_SAMPLE_SLOT_MANAGEMENT_SLOTS_PER_BANK 2

/* The supported SubCodes bit map. By default this sample supports the required SubCodes plus
 * the optional GetCSR, ManageBank, ManageSlot, and SetCertificate SubCodes. The Integrator can
 * override this global to advertise a different set of SubCodes. The bit position corresponds
 * to the SubCode value. */
uint8_t m_libspdm_slot_management_sub_code_bitmap[8] = {
    /* byte 0: SubCodes 0x00 - 0x07, containing the required SubCodes and GetCSR (0x04). */
    (uint8_t)((1 << SPDM_SLOT_MANAGEMENT_SUBCODE_SUPPORTED_SUBCODES) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_INFO) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_BANK_DETAILS) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CERTIFICATE_CHAIN) |
              (1 << SPDM_SLOT_MANAGEMENT_SUBCODE_GET_CSR)),
    0, 0, 0,
    /* byte 4: SubCodes 0x20 - 0x27, containing ManageBank (0x20), ManageSlot (0x21), and
     * SetCertificate (0x22). */
    (uint8_t)((1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_BANK % 8)) |
              (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_MANAGE_SLOT % 8)) |
              (1 << (SPDM_SLOT_MANAGEMENT_SUBCODE_SET_CERTIFICATE % 8))),
    0, 0, 0
};

/* The non-Selected Bank attribute bits the sample reports. By default this sample supports
 * configuration of the asymmetric algorithm for a Bank via the ManageBank SubCode, so
 * ConfigAlgo is set. The Selected attribute is computed per Bank (see below) and is not part
 * of this value. The Integrator can override this global to advertise different attributes. */
uint8_t m_libspdm_slot_management_bank_attributes =
    SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO;

/* A single slot within a Bank: the key pair bound to it. Whether the slot is populated with a
 * certificate chain is not cached here; it is derived on demand from the certificate store (NVM
 * file then static bundle), the same single source of truth the base SET_CERTIFICATE flow uses. */
typedef struct {
    uint8_t slot_id;         /* Wire SlotID (0-7), as carried in SLOT_MANAGEMENT messages. */
    uint8_t key_pair_id;     /* KeyPairID of the key pair associated with this slot. */
} libspdm_slot_management_sample_slot_t;

/* A Bank: one asymmetric algorithm plus the slots (key pairs) that use that algorithm. */
typedef struct {
    uint32_t asym_algo;      /* The Bank's traditional algorithm (Table 115 encoding), or 0. */
    uint32_t pqc_asym_algo;  /* The Bank's PQC algorithm (Table 116 encoding), or 0. */
    /* The algorithms the Bank could be configured to (Table 151 AsymAlgoCapabilities /
     * PqcAsymAlgoCapabilities), taken from the Bank's key pair. The Bank's current algorithm is
     * one of these bits; ManageBank ConfigAlgo may switch to any other bit that is not already
     * assigned to another Bank (see AvailableAsymAlgo). */
    uint32_t asym_algo_capabilities;
    uint32_t pqc_asym_algo_capabilities;
    uint8_t num_slots;
    libspdm_slot_management_sample_slot_t slots[SPDM_MAX_SLOT_COUNT];
} libspdm_slot_management_sample_bank_t;

/* The maximum number of Banks this sample reports. The sample maps one Bank per distinct key
 * pair algorithm, so this must be at least the number of distinct algorithms among the key
 * pairs. */
#define LIBSPDM_SAMPLE_SLOT_MANAGEMENT_BANK_COUNT 16

static libspdm_slot_management_sample_bank_t
    m_slot_management_bank[LIBSPDM_SAMPLE_SLOT_MANAGEMENT_BANK_COUNT];
static uint8_t m_slot_management_bank_count = 0;
static bool m_slot_management_bank_initialized = false;

/* Build the Bank table by grouping the key pairs reported by GET_KEY_PAIR_INFO according to
 * their currently configured asymmetric algorithm. */
static void libspdm_slot_management_init_banks(void *spdm_context)
{
    uint8_t total_key_pairs;
    uint8_t key_pair_index;
    uint8_t bank_index;

    if (m_slot_management_bank_initialized) {
        return;
    }

    m_slot_management_bank_count = 0;
    /* total_key_pairs is reported by libspdm_read_key_pair_info() itself (it has no separate query),
     * so it is set on the first read and then bounds the loop. Start at 0 so the loop runs at least
     * the first iteration (key pair 1). */
    total_key_pairs = 0;

    for (key_pair_index = 0;
         (key_pair_index == 0) || (key_pair_index < total_key_pairs);
         key_pair_index++) {
        uint16_t capabilities;
        uint16_t key_usage_capabilities;
        uint16_t current_key_usage;
        uint32_t asym_algo_capabilities;
        uint32_t current_asym_algo;
        uint32_t pqc_asym_algo_capabilities;
        uint32_t current_pqc_asym_algo;
        uint8_t assoc_cert_slot_mask;
        libspdm_slot_management_sample_bank_t *bank;

        if (!libspdm_read_key_pair_info(
                spdm_context, (uint8_t)(key_pair_index + 1),
                &total_key_pairs,
                &capabilities, &key_usage_capabilities, &current_key_usage,
                &asym_algo_capabilities, &current_asym_algo,
                &pqc_asym_algo_capabilities, &current_pqc_asym_algo,
                &assoc_cert_slot_mask, NULL, NULL)) {
            continue;
        }

        /* A key pair with no configured algorithm does not belong to any Bank. */
        if ((current_asym_algo == 0) && (current_pqc_asym_algo == 0)) {
            continue;
        }

        /* Find an existing Bank for this algorithm, or create a new one. */
        bank = NULL;
        for (bank_index = 0; bank_index < m_slot_management_bank_count; bank_index++) {
            if ((m_slot_management_bank[bank_index].asym_algo == current_asym_algo) &&
                (m_slot_management_bank[bank_index].pqc_asym_algo == current_pqc_asym_algo)) {
                bank = &m_slot_management_bank[bank_index];
                break;
            }
        }
        if (bank == NULL) {
            uint8_t slot_index;

            if (m_slot_management_bank_count >= LIBSPDM_SAMPLE_SLOT_MANAGEMENT_BANK_COUNT) {
                continue;
            }
            bank = &m_slot_management_bank[m_slot_management_bank_count];
            bank->asym_algo = current_asym_algo;
            bank->pqc_asym_algo = current_pqc_asym_algo;
            /* The Bank can be configured to any algorithm its key pair supports (the Bank's
             * current algorithm is one of these). ManageBank ConfigAlgo uses this, restricted to
             * algorithms not already assigned to another Bank (AvailableAsymAlgo). */
            bank->asym_algo_capabilities = asym_algo_capabilities;
            bank->pqc_asym_algo_capabilities = pqc_asym_algo_capabilities;
            bank->num_slots = 0;
            m_slot_management_bank_count++;

            /* Expose the wire SlotIDs the sample certificate store can back (0 and 1). The
             * SlotID stored here is the value carried on the wire, not a packed index. The
             * Bank's key pair is associated with each slot. */
            for (slot_index = 0;
                 slot_index < LIBSPDM_SAMPLE_SLOT_MANAGEMENT_SLOTS_PER_BANK;
                 slot_index++) {
                bank->slots[slot_index].slot_id = slot_index;
                bank->slots[slot_index].key_pair_id = (uint8_t)(key_pair_index + 1);
                bank->num_slots++;
            }
        }
    }

    m_slot_management_bank_initialized = true;
}

/* Return the Bank with the given bank_id, or NULL if it does not exist. */
static libspdm_slot_management_sample_bank_t *libspdm_slot_management_get_bank(
    void *spdm_context, uint8_t bank_id)
{
    libspdm_slot_management_init_banks(spdm_context);
    if (bank_id >= m_slot_management_bank_count) {
        return NULL;
    }
    return &m_slot_management_bank[bank_id];
}

/* Return the slot with the given Bank-local slot_id in the Bank, or NULL if it does not
 * exist. */
static libspdm_slot_management_sample_slot_t *libspdm_slot_management_get_slot(
    libspdm_slot_management_sample_bank_t *bank, uint8_t slot_id)
{
    uint8_t index;
    for (index = 0; index < bank->num_slots; index++) {
        if (bank->slots[index].slot_id == slot_id) {
            return &bank->slots[index];
        }
    }
    return NULL;
}

bool libspdm_read_slot_management_supported_subcodes(
    void *spdm_context,
    uint8_t *sub_code_bitmap)
{
    if (sub_code_bitmap == NULL) {
        return false;
    }

    libspdm_copy_mem(sub_code_bitmap, 8,
                     m_libspdm_slot_management_sub_code_bitmap,
                     sizeof(m_libspdm_slot_management_sub_code_bitmap));

    return true;
}

/* Map a key pair AsymAlgoCapabilities bit (Table 115) to a negotiated BaseAsymAlgo value
 * (Table 113), used to select the certificate file for the Bank's algorithm. RSA maps to the
 * RSASSA encoding. Returns 0 if there is no match. */
static uint32_t libspdm_slot_management_key_pair_asym_to_base_asym(uint32_t key_pair_asym_algo)
{
    switch (key_pair_asym_algo) {
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519;
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448:
        return SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    default:
        return 0;
    }
}

/* Map a negotiated BaseAsymAlgo value (Table 113) to the corresponding key pair
 * AsymAlgoCapabilities bit (Table 115). Returns 0 if there is no match. */
static uint32_t libspdm_slot_management_base_asym_to_key_pair_asym(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
    default:
        return 0;
    }
}

/* Map a key pair PqcAsymAlgoCapabilities bit (Table 116) to a negotiated PqcAsymAlgo value
 * (Table 117), used to select the certificate file for the Bank's PQC algorithm. The two
 * encodings happen to coincide today, but the specification does not guarantee that, so this
 * sample maps them explicitly rather than assuming they are equal. Returns 0 if there is no
 * match. */
static uint32_t libspdm_slot_management_key_pair_pqc_asym_to_pqc_asym(
    uint32_t key_pair_pqc_asym_algo)
{
    switch (key_pair_pqc_asym_algo) {
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_128S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_128S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_128F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_128F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_192S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_192S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_192F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_192F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_256S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_256S:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_256F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F;
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_256F:
        return SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F;
    default:
        return 0;
    }
}

/* Map a negotiated PqcAsymAlgo value (Table 117) to the corresponding key pair
 * PqcAsymAlgoCapabilities bit (Table 116). The two encodings happen to coincide today, but the
 * specification does not guarantee that, so this sample maps them explicitly. Returns 0 if there
 * is no match. */
static uint32_t libspdm_slot_management_pqc_asym_to_key_pair_pqc_asym(uint32_t pqc_asym_algo)
{
    switch (pqc_asym_algo) {
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_128S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_128S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_128F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_128F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_192S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_192S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_192F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_192F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_256S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_256S;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHA2_256F;
    case SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F:
        return SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_SLH_DSA_SHAKE_256F;
    default:
        return 0;
    }
}

/* A Bank is "Selected" if its algorithm matches the algorithm negotiated in the last
 * successful ALGORITHMS response. Both the traditional and the PQC algorithm encodings (the
 * Bank stores the key pair encoding) must be mapped to the negotiated encoding to compare. */
static bool libspdm_slot_management_bank_is_selected(
    libspdm_context_t *context, const libspdm_slot_management_sample_bank_t *bank)
{
    if (bank->pqc_asym_algo != 0) {
        return (bank->pqc_asym_algo == libspdm_slot_management_pqc_asym_to_key_pair_pqc_asym(
                    context->connection_info.algorithm.pqc_asym_algo));
    }
    if (bank->asym_algo != 0) {
        return (bank->asym_algo == libspdm_slot_management_base_asym_to_key_pair_asym(
                    context->connection_info.algorithm.base_asym_algo));
    }
    return false;
}

/* Sample-internal: resolve a SetCertificate Bank for libspdm_update_local_cert_chain (set_cert.c).
 * See slot_management_internal.h. */
bool libspdm_slot_management_sample_classify_bank(
    void *spdm_context, uint8_t bank_id, bool *is_selected)
{
    libspdm_context_t *context;
    libspdm_slot_management_sample_bank_t *bank;

    context = spdm_context;
    bank = libspdm_slot_management_get_bank(context, bank_id);
    if (bank == NULL) {
        return false;
    }
    *is_selected = libspdm_slot_management_bank_is_selected(context, bank);
    return true;
}

/* Build the certificate-chain NVM file name for a (Bank, slot), matching the naming scheme used
 * by libspdm_write_certificate_to_nvm (set_cert.c). When bank_id is
 * LIBSPDM_SLOT_MANAGEMENT_SAMPLE_NVM_LEGACY_BANK the legacy per-slot name (the one the base
 * SET_CERTIFICATE flow writes) is produced; otherwise the Bank-qualified name is produced. */
static void libspdm_slot_management_cert_nvm_file_name(
    uint8_t bank_id, uint8_t slot_id, char *file_name, size_t file_name_size)
{
    if (bank_id == LIBSPDM_SLOT_MANAGEMENT_SAMPLE_NVM_LEGACY_BANK) {
        snprintf(file_name, file_name_size, "slot_id_%u_cert_chain.der",
                 (unsigned)(slot_id & 0xF));
    } else {
        snprintf(file_name, file_name_size, "bank_id_%03u_slot_id_%u_cert_chain.der",
                 (unsigned)bank_id, (unsigned)(slot_id & 0xF));
    }
}

/* Outcome of looking up a runtime-provisioned certificate chain in NVM for a (Bank, slot). */
typedef enum {
    /* No NVM file exists: the slot was never provisioned at runtime. The caller should fall back
     * to the static certificate store (the factory-provisioned chain). */
    LIBSPDM_SLOT_MGMT_NVM_ABSENT,
    /* A zero-length NVM file exists: the slot was erased (SET_CERTIFICATE / ManageSlot Erase writes
     * a zero-length file, as libspdm_write_certificate_to_nvm does for an erase). The slot is
     * unpopulated and the caller shall NOT fall back to the static store. */
    LIBSPDM_SLOT_MGMT_NVM_ERASED,
    /* A non-empty NVM file exists and a full certificate chain was reconstructed from it. */
    LIBSPDM_SLOT_MGMT_NVM_FOUND,
} libspdm_slot_management_nvm_result_t;

/* Erase any runtime-provisioned certificate chain for a (Bank, slot) by writing a zero-length NVM
 * file. This matches the sample SET_CERTIFICATE erase, which calls
 * libspdm_write_certificate_to_nvm(.., NULL, 0, ..) and so leaves a zero-length file.
 * libspdm_slot_management_read_provisioned_cert_chain then reports the slot as erased. */
static void libspdm_slot_management_erase_provisioned_cert_chain(uint8_t bank_id, uint8_t slot_id)
{
    char file_name[40];

    libspdm_slot_management_cert_nvm_file_name(bank_id, slot_id, file_name, sizeof(file_name));
    libspdm_write_output_file(file_name, NULL, 0);
}

/* Try to read a runtime-provisioned certificate chain for a (Bank, slot) from NVM, i.e. one that
 * was written by a SET_CERTIFICATE (legacy, BankID-less) or a SLOT_MANAGEMENT SetCertificate
 * (Bank-qualified) operation. The NVM file holds the raw certificate chain (concatenated DER
 * certificates), the same input format as the static bundle files, so the full SPDM certificate
 * chain (Table 39: spdm_cert_chain_t header + root hash + certs) is reconstructed here.
 *
 * Returns one of libspdm_slot_management_nvm_result_t: ABSENT (no file -> caller falls back to the
 * static store), ERASED (zero-length file -> slot unpopulated, no fallback), or FOUND (chain
 * reconstructed into *cert_chain, which the caller owns and must free). A reconstruction failure on
 * a non-empty file is reported as ERASED so the caller does not serve a stale static chain for a
 * slot that was provisioned with an unreadable chain. */
static libspdm_slot_management_nvm_result_t libspdm_slot_management_read_provisioned_cert_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    uint8_t bank_id, uint8_t slot_id, void **cert_chain, size_t *cert_chain_size)
{
    char file_name[40];
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *chain;
    size_t chain_size;
    size_t digest_size;
    const uint8_t *root_cert;
    size_t root_cert_len;

    *cert_chain = NULL;
    *cert_chain_size = 0;

    libspdm_slot_management_cert_nvm_file_name(bank_id, slot_id, file_name, sizeof(file_name));

    res = libspdm_read_input_file(file_name, &file_data, &file_size);
    if (!res) {
        /* No runtime-provisioned chain for this (Bank, slot): fall back to the static store. */
        return LIBSPDM_SLOT_MGMT_NVM_ABSENT;
    }
    /* A zero-length provisioned file represents an erased slot (no certificate chain). */
    if (file_size == 0) {
        free(file_data);
        return LIBSPDM_SLOT_MGMT_NVM_ERASED;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    chain = (void *)malloc(chain_size);
    if (chain == NULL) {
        free(file_data);
        return LIBSPDM_SLOT_MGMT_NVM_ERASED;
    }
    chain->length = (uint32_t)chain_size;

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(chain);
        return LIBSPDM_SLOT_MGMT_NVM_ERASED;
    }
    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len, (uint8_t *)(chain + 1));
    if (!res) {
        free(file_data);
        free(chain);
        return LIBSPDM_SLOT_MGMT_NVM_ERASED;
    }
    libspdm_copy_mem((uint8_t *)chain + sizeof(spdm_cert_chain_t) + digest_size,
                     chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);
    free(file_data);

    *cert_chain = chain;
    *cert_chain_size = chain_size;
    return LIBSPDM_SLOT_MGMT_NVM_FOUND;
}

/* Read the certificate chain for a Bank slot, selected by the Bank's asymmetric algorithm and
 * the Bank-local SlotID. The caller takes ownership of *cert_chain and must free it.
 *
 * Per DSP0274, the slots in the Bank selected during algorithm negotiation are the same slots
 * that GET_CERTIFICATE/SET_CERTIFICATE operate on, so a runtime SET_CERTIFICATE (or SLOT_MANAGEMENT
 * SetCertificate) must be visible here. The lookup therefore prefers a runtime-provisioned chain
 * in NVM and only falls back to the static certificate store when none has been provisioned:
 *   1. the Bank-qualified NVM file (SLOT_MANAGEMENT SetCertificate for this Bank),
 *   2. for the Selected Bank, the legacy NVM file (base SET_CERTIFICATE, which has no BankID),
 *   3. the static bundle for the Bank's algorithm. */
static bool libspdm_slot_management_read_slot_cert_chain(
    libspdm_context_t *context, const libspdm_slot_management_sample_bank_t *bank,
    const libspdm_slot_management_sample_slot_t *slot,
    void **cert_chain, size_t *cert_chain_size)
{
    uint32_t base_hash_algo;
    uint32_t base_asym_algo = 0;
    uint32_t pqc_asym_algo = 0;
    uint8_t bank_id;
    libspdm_slot_management_nvm_result_t nvm_result;

    *cert_chain = NULL;
    *cert_chain_size = 0;

    base_hash_algo = context->connection_info.algorithm.base_hash_algo;

    /* Map the Bank's stored key-pair algorithm encoding to the negotiated encoding used by the
     * certificate read APIs. */
    if (bank->pqc_asym_algo != 0) {
        pqc_asym_algo = libspdm_slot_management_key_pair_pqc_asym_to_pqc_asym(bank->pqc_asym_algo);
        if (pqc_asym_algo == 0) {
            return false;
        }
    } else if (bank->asym_algo != 0) {
        base_asym_algo = libspdm_slot_management_key_pair_asym_to_base_asym(bank->asym_algo);
        if (base_asym_algo == 0) {
            return false;
        }
    } else {
        return false;
    }

    /* The Bank index is the BankID used to qualify the NVM file name. */
    bank_id = (uint8_t)(bank - m_slot_management_bank);

    /* 1. Bank-qualified runtime-provisioned chain (SLOT_MANAGEMENT SetCertificate). FOUND returns
     * the chain; ERASED reports the slot unpopulated (no fallback); ABSENT tries the next source. */
    nvm_result = libspdm_slot_management_read_provisioned_cert_chain(
        base_hash_algo, base_asym_algo, pqc_asym_algo, bank_id, slot->slot_id,
        cert_chain, cert_chain_size);
    if (nvm_result == LIBSPDM_SLOT_MGMT_NVM_FOUND) {
        return true;
    }
    if (nvm_result == LIBSPDM_SLOT_MGMT_NVM_ERASED) {
        return false;
    }

    /* 2. For the Selected Bank, the legacy SET_CERTIFICATE chain (written with no BankID) is the
     * in-use slot's chain and must be reflected here. */
    if (libspdm_slot_management_bank_is_selected(context, bank)) {
        nvm_result = libspdm_slot_management_read_provisioned_cert_chain(
            base_hash_algo, base_asym_algo, pqc_asym_algo,
            LIBSPDM_SLOT_MANAGEMENT_SAMPLE_NVM_LEGACY_BANK, slot->slot_id,
            cert_chain, cert_chain_size);
        if (nvm_result == LIBSPDM_SLOT_MGMT_NVM_FOUND) {
            return true;
        }
        if (nvm_result == LIBSPDM_SLOT_MGMT_NVM_ERASED) {
            return false;
        }
    }

    /* 3. Fall back to the static certificate store for the Bank's algorithm (base_asym_algo /
     * pqc_asym_algo were already mapped to the negotiated encoding above). */
    if (pqc_asym_algo != 0) {
        return libspdm_read_pqc_responder_public_certificate_chain_per_slot(
            slot->slot_id, base_hash_algo, pqc_asym_algo,
            cert_chain, cert_chain_size, NULL, NULL);
    }
    if (base_asym_algo != 0) {
        return libspdm_read_responder_public_certificate_chain_per_slot(
            slot->slot_id, base_hash_algo, base_asym_algo,
            cert_chain, cert_chain_size, NULL, NULL);
    }

    return false;
}

bool libspdm_read_slot_management_bank_info(
    void *spdm_context,
    uint8_t *num_bank_elements,
    spdm_slot_management_bank_element_struct_t *bank_elements)
{
    libspdm_context_t *context;
    uint8_t bank_index;

    if ((num_bank_elements == NULL) || (bank_elements == NULL)) {
        return false;
    }

    context = spdm_context;
    libspdm_slot_management_init_banks(context);
    if (*num_bank_elements < m_slot_management_bank_count) {
        return false;
    }

    for (bank_index = 0; bank_index < m_slot_management_bank_count; bank_index++) {
        const libspdm_slot_management_sample_bank_t *bank =
            &m_slot_management_bank[bank_index];
        uint8_t slot_mask = 0;
        uint8_t index;

        for (index = 0; index < bank->num_slots; index++) {
            void *cert_chain;
            size_t cert_chain_size;

            /* A slot exists in the Bank only if its certificate chain is actually readable
             * for the Bank's algorithm (the build may not support every algorithm). */
            if (libspdm_slot_management_read_slot_cert_chain(
                    context, bank, &bank->slots[index], &cert_chain, &cert_chain_size)) {
                slot_mask |= (uint8_t)(1 << bank->slots[index].slot_id);
                free(cert_chain);
            }
        }

        bank_elements[bank_index].element_length = SPDM_SLOT_MANAGEMENT_BANK_ELEMENT_LENGTH;
        bank_elements[bank_index].bank_id = bank_index;
        bank_elements[bank_index].slot_mask = slot_mask;
        /* This sample does not allow slots to be modified by the Requester. */
        bank_elements[bank_index].modifiable_slot_mask = 0;
    }

    *num_bank_elements = m_slot_management_bank_count;

    return true;
}

bool libspdm_read_slot_management_bank_details(
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
    uint8_t *slot_digests)
{
    libspdm_context_t *context;
    libspdm_slot_management_sample_bank_t *bank;
    uint8_t slot_index;
    uint8_t slot_count;
    uint32_t hash_size;

    if ((bank_attributes == NULL) || (asym_algo_capabilities == NULL) ||
        (current_asym_algo == NULL) || (available_asym_algo == NULL) ||
        (pqc_asym_algo_capabilities == NULL) || (current_pqc_asym_algo == NULL) ||
        (available_pqc_asym_algo == NULL) || (num_slot_elements == NULL) ||
        (slot_elements == NULL) || (slot_digest_size == NULL) || (slot_digests == NULL)) {
        return false;
    }

    context = spdm_context;
    bank = libspdm_slot_management_get_bank(context, bank_id);
    if (bank == NULL) {
        return false;
    }

    /* The Bank's currently configured algorithm. */
    *current_asym_algo = bank->asym_algo;
    *current_pqc_asym_algo = bank->pqc_asym_algo;

    /* The Bank attributes are taken from the (overridable) global, plus the Selected bit which
     * is computed per Bank. */
    *bank_attributes = m_libspdm_slot_management_bank_attributes;
    if (libspdm_slot_management_bank_is_selected(context, bank)) {
        *bank_attributes |= SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED;
    } else {
        *bank_attributes &= ~SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_SELECTED;
    }

    /* Per the specification, when ConfigAlgo is 0 the Responder shall set the *Capabilities and
     * Available* algorithm fields to 0. When ConfigAlgo is 1, this sample reports the Bank's
     * key-pair-supported algorithms as its Capabilities. The Available* fields are the Capabilities
     * with the algorithms already assigned to ANOTHER Bank cleared (DSP0274 Table 151): an
     * algorithm a different Bank currently holds is not available for this Bank. */
    if ((*bank_attributes & SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO) == 0) {
        *asym_algo_capabilities = 0;
        *available_asym_algo = 0;
        *pqc_asym_algo_capabilities = 0;
        *available_pqc_asym_algo = 0;
    } else {
        uint32_t other_asym_algo = 0;
        uint32_t other_pqc_asym_algo = 0;
        uint8_t other_index;

        for (other_index = 0; other_index < m_slot_management_bank_count; other_index++) {
            if (&m_slot_management_bank[other_index] != bank) {
                other_asym_algo |= m_slot_management_bank[other_index].asym_algo;
                other_pqc_asym_algo |= m_slot_management_bank[other_index].pqc_asym_algo;
            }
        }

        *asym_algo_capabilities = bank->asym_algo_capabilities;
        *available_asym_algo = bank->asym_algo_capabilities & ~other_asym_algo;
        *pqc_asym_algo_capabilities = bank->pqc_asym_algo_capabilities;
        *available_pqc_asym_algo = bank->pqc_asym_algo_capabilities & ~other_pqc_asym_algo;
    }

    hash_size = libspdm_get_hash_size(context->connection_info.algorithm.base_hash_algo);

    slot_count = 0;
    for (slot_index = 0; slot_index < bank->num_slots; slot_index++) {
        const libspdm_slot_management_sample_slot_t *slot = &bank->slots[slot_index];
        spdm_slot_management_slot_element_struct_t *slot_element;
        uint8_t *digest;
        void *cert_chain;
        size_t cert_chain_size;

        /* A slot is reported as populated only if its certificate chain is readable for the Bank's
         * algorithm. An erased slot (zero-length NVM file) and an unreadable slot both report no
         * chain, so they are skipped, matching the SlotMask from GetBankInfo. */
        if (!libspdm_slot_management_read_slot_cert_chain(
                context, bank, slot, &cert_chain, &cert_chain_size)) {
            continue;
        }
        if (slot_count >= *num_slot_elements) {
            free(cert_chain);
            return false;
        }

        /* Fill the fixed SlotElement fields (the Responder sets element_length). */
        slot_element = &slot_elements[slot_count];
        slot_element->element_length = 0;
        slot_element->slot_id = slot->slot_id;
        slot_element->reserved = 0;
        slot_element->slot_attributes = SPDM_SLOT_MANAGEMENT_SLOT_ATTRIBUTE_PROVISIONED;
        /* The KeyPairID of the key pair associated with this slot. Per Table 152 this is only
         * populated when MULTI_KEY_CONN_RSP is true; otherwise it is 0. Reporting distinct
         * KeyPairIDs for slots in the same Bank is how the multi-key feature is shown. */
        if (context->connection_info.multi_key_conn_rsp) {
            slot_element->key_pair_id = slot->key_pair_id;
        } else {
            slot_element->key_pair_id = 0;
        }
        slot_element->certificate_info = 0;
        slot_element->reserved2 = 0;
        slot_element->key_usage = 0;
        slot_element->reserved3 = 0;
        slot_element->slot_size = (uint32_t)cert_chain_size;

        /* The digest of the slot's certificate chain, returned separately at a stride of
         * *slot_digest_size (the negotiated hash size). */
        digest = slot_digests + (size_t)slot_count * (*slot_digest_size);
        if (!libspdm_hash_all(context->connection_info.algorithm.base_hash_algo,
                              cert_chain, cert_chain_size, digest)) {
            free(cert_chain);
            return false;
        }
        free(cert_chain);
        slot_count++;
    }

    *num_slot_elements = slot_count;
    *slot_digest_size = hash_size;

    return true;
}

bool libspdm_read_slot_management_certificate_chain(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t slot_id,
    size_t *cert_chain_size,
    void *cert_chain)
{
    libspdm_context_t *context;
    libspdm_slot_management_sample_bank_t *bank;
    libspdm_slot_management_sample_slot_t *slot;
    void *slot_cert_chain;
    size_t slot_cert_chain_size;

    if ((cert_chain_size == NULL) || (cert_chain == NULL)) {
        return false;
    }

    context = spdm_context;
    bank = libspdm_slot_management_get_bank(context, bank_id);
    if (bank == NULL) {
        return false;
    }
    slot = libspdm_slot_management_get_slot(bank, slot_id);
    if (slot == NULL) {
        return false;
    }

    /* The certificate chain is selected by the Bank's algorithm and the Bank-local SlotID. It
     * is read on demand and does not need to be provisioned into the SPDM context. */
    if (!libspdm_slot_management_read_slot_cert_chain(
            context, bank, slot, &slot_cert_chain, &slot_cert_chain_size)) {
        return false;
    }

    if (slot_cert_chain_size > *cert_chain_size) {
        free(slot_cert_chain);
        return false;
    }

    libspdm_copy_mem(cert_chain, *cert_chain_size, slot_cert_chain, slot_cert_chain_size);
    *cert_chain_size = slot_cert_chain_size;

    free(slot_cert_chain);

    return true;
}

bool libspdm_write_slot_management_bank(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t operation,
    uint32_t select_asym_algo,
    uint32_t select_pqc_asym_algo,
    uint8_t *bank_result)
{
    libspdm_context_t *context;
    libspdm_slot_management_sample_bank_t *bank;
    uint8_t index;

    context = spdm_context;

    if (bank_result != NULL) {
        *bank_result = LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_INVALID;
    }

    bank = libspdm_slot_management_get_bank(spdm_context, bank_id);
    if (bank == NULL) {
        return false;
    }

    if (operation != SPDM_SLOT_MANAGEMENT_MANAGE_BANK_OPERATION_CONFIG_ALGO) {
        return false;
    }

    /* At most one asymmetric algorithm (traditional or PQC) may be selected. */
    if ((select_asym_algo != 0) && (select_pqc_asym_algo != 0)) {
        return false;
    }

    /* Selecting the Bank's existing algorithm is an idempotent no-op and always succeeds. */
    if ((select_asym_algo == bank->asym_algo) &&
        (select_pqc_asym_algo == bank->pqc_asym_algo)) {
        if (bank_result != NULL) {
            *bank_result = LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_OK;
        }
        return true;
    }

    /* Reconfiguring the Bank to a different algorithm requires its slots to be unprovisioned. A
     * slot is provisioned until its certificate chain is removed (a ManageSlot Erase writes a
     * zero-length NVM file), so any slot whose chain is still readable blocks the reconfiguration.
     * Per the specification, that condition is reported as InvalidState. This is checked before the
     * algorithm-uniqueness check below: a Bank that cannot be reconfigured at all is reported as
     * InvalidState regardless of the requested algorithm. */
    for (index = 0; index < bank->num_slots; index++) {
        void *cert_chain;
        size_t cert_chain_size;

        if (libspdm_slot_management_read_slot_cert_chain(
                context, bank, &bank->slots[index], &cert_chain, &cert_chain_size)) {
            free(cert_chain);
            if (bank_result != NULL) {
                *bank_result = LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_INVALID_STATE;
            }
            return false;
        }
    }

    /* A Bank's configured algorithm (CurrentAlgo) is unique across Banks: per DSP0274 Table 145
     * ConfigAlgo, if another Bank is already configured for the selected algorithm the Responder
     * shall return ERROR(InvalidRequest). bank_result is already INVALID, which the Responder maps
     * to InvalidRequest. (The selecting-its-own-algorithm case was handled above.) */
    for (index = 0; index < m_slot_management_bank_count; index++) {
        if ((&m_slot_management_bank[index] != bank) &&
            (m_slot_management_bank[index].asym_algo == select_asym_algo) &&
            (m_slot_management_bank[index].pqc_asym_algo == select_pqc_asym_algo)) {
            return false;
        }
    }

    /* The Bank is unprovisioned, so its algorithm may be reconfigured. Accept only an algorithm
     * the device can actually back, i.e. one that maps to a certificate the sample store can
     * provide. Exactly one of select_asym_algo / select_pqc_asym_algo is non-zero here. */
    if (select_pqc_asym_algo != 0) {
        if (libspdm_slot_management_key_pair_pqc_asym_to_pqc_asym(select_pqc_asym_algo) == 0) {
            return false;
        }
        bank->asym_algo = 0;
        bank->pqc_asym_algo = select_pqc_asym_algo;
    } else if (select_asym_algo != 0) {
        if (libspdm_slot_management_key_pair_asym_to_base_asym(select_asym_algo) == 0) {
            return false;
        }
        bank->asym_algo = select_asym_algo;
        bank->pqc_asym_algo = 0;
    } else {
        /* Neither algorithm selected: nothing to configure. */
        return false;
    }

    if (bank_result != NULL) {
        *bank_result = LIBSPDM_SLOT_MANAGEMENT_BANK_RESULT_OK;
    }
    return true;
}

bool libspdm_write_slot_management_slot(
    void *spdm_context,
    uint8_t bank_id,
    uint8_t slot_id,
    uint8_t operation,
    bool *need_reset,
    bool *is_busy)
{
    libspdm_context_t *context;
    libspdm_slot_management_sample_bank_t *bank;
    libspdm_slot_management_sample_slot_t *slot;

    context = spdm_context;

    if (is_busy != NULL) {
        *is_busy = false;
    }
    /* Mirror the sample SET_CERTIFICATE behavior: the Responder pre-sets *need_reset to whether it
     * advertises CERT_INSTALL_RESET_CAP, and this sample leaves it unchanged. So the Erase requires
     * a reset to complete exactly when CERT_INSTALL_RESET_CAP is advertised; otherwise it completes
     * immediately. */

    /* Defense in depth: ManageSlot is destructive, so this sample enforces the access-control
     * rule for slots 1-7 (DSP0274 "Certificate slot management") here as well as in the
     * Responder. Slots 1-7 may only be managed in a trusted environment or a secure session; a
     * secure session is an accepted alternative to a trusted environment. */
    if (slot_id != 0) {
        if (!libspdm_is_in_trusted_environment(spdm_context) &&
            !context->last_spdm_request_session_id_valid) {
            return false;
        }
    }

    bank = libspdm_slot_management_get_bank(spdm_context, bank_id);
    if (bank == NULL) {
        return false;
    }
    slot = libspdm_slot_management_get_slot(bank, slot_id);
    if (slot == NULL) {
        return false;
    }

    if (operation != SPDM_SLOT_MANAGEMENT_MANAGE_SLOT_OPERATION_ERASE) {
        return false;
    }

    /* Erase: remove the slot's certificate chain by writing a zero-length NVM file, exactly as the
     * base SET_CERTIFICATE erase does (libspdm_write_certificate_to_nvm with a NULL chain).
     * Subsequent GetBankInfo/GetBankDetails/GetCertificateChain for this (Bank, slot) read no chain
     * and report it as unpopulated. Per DSP0274, the slots in the Selected Bank are the same slots
     * that GET_CERTIFICATE operates on, so for the Selected Bank also erase the BankID-less legacy
     * file the base SET_CERTIFICATE flow uses, keeping the two views consistent. */
    libspdm_slot_management_erase_provisioned_cert_chain(bank_id, slot_id);
    if (libspdm_slot_management_bank_is_selected(context, bank)) {
        libspdm_slot_management_erase_provisioned_cert_chain(
            LIBSPDM_SLOT_MANAGEMENT_SAMPLE_NVM_LEGACY_BANK, slot_id);
    }

    return true;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */
