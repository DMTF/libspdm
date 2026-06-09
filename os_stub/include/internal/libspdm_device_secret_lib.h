/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__
#define __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__

#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "hal/library/cryptlib_ext.h"
#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/key_pair_info.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "hal/library/requester/psklib.h"
#include "hal/library/debuglib.h"
#include "hal/library/cryptlib.h"
#include "industry_standard/cxl_tsp.h"

/* for meas test */
#define LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER 4
#define LIBSPDM_MEASUREMENT_BLOCK_NUMBER (LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER /*Index - 1~4*/ + \
                                          1 /*SVN - 0x10*/ + \
                                          1 /*HEM - 0x11*/ + \
                                          1 /*Manifest - 0xFD*/ + 1 /*DEVICE_MODE - 0xFE*/)
#define LIBSPDM_MEASUREMENT_RAW_DATA_SIZE 72
#define LIBSPDM_MEASUREMENT_MANIFEST_SIZE 128
#define LIBSPDM_MEASUREMENT_INDEX_SVN 0x10
#define LIBSPDM_MEASUREMENT_INDEX_HEM 0x11

/* for psk test */
#define LIBSPDM_TEST_PSK_DATA_STRING "TestPskData"
#define LIBSPDM_TEST_PSK_HINT_STRING "TestPskHint"

/* for cert test */
#define LIBSPDM_TEST_CERT_MAXINT16 1
#define LIBSPDM_TEST_CERT_MAXUINT16 2
#define LIBSPDM_LIBSPDM_TEST_CERT_MAXUINT16_LARGER 3
#define LIBSPDM_TEST_CERT_SMALL 4

/* Multi-key example: a slot is provisioned with a DIFFERENT leaf key than slot 0 / slot 1
 * (bundle_responder.certchain4.der, end_responder4.key). That slot is SlotID 4, with SlotIDs 2 and 3
 * left empty, to also demonstrate a NON-CONTIGUOUS slot configuration (SlotIDs may have gaps).
 *
 * KeyPairIDs, in contrast, must be contiguous 1..TotalKeyPairs without gaps and each KeyPairID has
 * one fixed algorithm (DSP0274 "Key pair info"). So the KeyPairID for slot 4 is NOT a fixed value:
 * it is the (device-global) id of the negotiated algorithm's SECONDARY key pair. Use
 * libspdm_get_key_pair_id_by_slot() to resolve it. */

/* "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 1" means use the RAW private key only
 * "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 0" means controlled by g_private_key_mode
 **/
#define LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY 0
/* "g_private_key_mode = 1" means use the PEM mode
 * "g_private_key_mode = 0" means use the RAW mode
 **/
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
extern bool g_private_key_mode;
#endif

/* Option to change signing algorithm to little endian. Default is big endian. */
#define LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN (0)

/* read pub cert */

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
                                                    uint32_t base_asym_algo,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
                                                         uint32_t base_hash_algo,
                                                         uint32_t base_asym_algo,
                                                         void **data, size_t *size,
                                                         void **hash,
                                                         size_t *hash_size);

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
                                                    uint16_t req_base_asym_alg,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size);

bool libspdm_read_responder_certificate(uint32_t base_asym_algo,
                                        void **data, size_t *size);

/* read pub cert pqc */

bool libspdm_read_pqc_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

/*This alias cert chain is entire, from root CA to leaf certificate.*/
bool libspdm_read_pqc_responder_public_certificate_chain_alias_cert(
    uint32_t base_hash_algo, uint32_t pqc_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_pqc_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t pqc_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_pqc_requester_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t req_pqc_asym_alg, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_pqc_responder_root_public_certificate(uint32_t base_hash_algo,
                                                        uint32_t pqc_asym_algo,
                                                        void **data, size_t *size,
                                                        void **hash,
                                                        size_t *hash_size);

bool libspdm_read_pqc_responder_root_public_certificate_slot(uint8_t slot_id,
                                                             uint32_t base_hash_algo,
                                                             uint32_t pqc_asym_algo,
                                                             void **data, size_t *size,
                                                             void **hash,
                                                             size_t *hash_size);

bool libspdm_read_pqc_requester_root_public_certificate(uint32_t base_hash_algo,
                                                        uint32_t req_pqc_asym_alg,
                                                        void **data, size_t *size,
                                                        void **hash,
                                                        size_t *hash_size);

bool libspdm_read_responder_pqc_certificate(uint32_t base_asym_algo,
                                            void **data, size_t *size);

/* read special cert */

bool libspdm_read_responder_public_certificate_chain_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
    void **data, size_t *size, void **hash,
    size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_by_size(
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
    void **data, size_t *size, void **hash,
    size_t *hash_size);

/* read pub key der */

bool libspdm_read_responder_public_key(
    uint32_t base_asym_algo, void **data, size_t *size);

bool libspdm_read_requester_public_key(
    uint16_t req_base_asym_alg, void **data, size_t *size);

/* read pub key der pqc */

bool libspdm_read_responder_pqc_public_key(
    uint32_t pqc_asym_algo, void **data, size_t *size);

bool libspdm_read_requester_pqc_public_key(
    uint32_t req_pqc_asym_alg, void **data, size_t *size);

/* read priv key pem */

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_private_key(uint32_t base_asym_algo,
                                        void **data, size_t *size);
/* Same as libspdm_read_responder_private_key, but selects the leaf key by key_pair_id so a slot
 * provisioned with a distinct key (the negotiated algorithm's secondary key pair -> end_responder4.key) signs with
 * that key. Any other key_pair_id uses the default end_responder.key. */
bool libspdm_read_responder_private_key_ex(uint32_t base_asym_algo, uint8_t key_pair_id,
                                           void **data, size_t *size);
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_read_requester_private_key(uint16_t req_base_asym_alg,
                                        void **data, size_t *size);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (...) */

/* read priv key pem pqc */

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_pqc_private_key(uint32_t pqc_asym_algo,
                                            void **data, size_t *size);
/* Same as libspdm_read_responder_pqc_private_key, but selects the leaf key by key_pair_id
 * (the negotiated algorithm's secondary key pair -> end_responder4.key). */
bool libspdm_read_responder_pqc_private_key_ex(uint32_t pqc_asym_algo, uint8_t key_pair_id,
                                               void **data, size_t *size);
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_read_requester_pqc_private_key(uint32_t req_pqc_asym_alg,
                                            void **data, size_t *size);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (...) */

/* read priv key raw data */

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo, void **context);

bool libspdm_get_requester_private_key_from_raw_data(uint32_t base_asym_algo, void **context);

/* read priv key raw data pqc */

bool libspdm_get_responder_pqc_private_key_from_raw_data(uint32_t pqc_asym_algo, void **context);

bool libspdm_get_requester_pqc_private_key_from_raw_data(uint32_t req_pqc_asym_algo, void **context);

/* key pairs */
#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
uint8_t libspdm_read_total_key_pairs(void *spdm_context);

/* Resolve the device-global KeyPairID (1..TotalKeyPairs) that backs slot_id under the connection's
 * negotiated algorithm (pqc_asym_algo if non-zero, otherwise base_asym_algo). Slots 0/1 map to the
 * algorithm's primary key pair, slot 4 to its secondary (the multi-key example). Returns 0 if none
 * matches. */
uint8_t libspdm_get_key_pair_id_by_slot(uint32_t base_asym_algo, uint32_t pqc_asym_algo,
                                        uint8_t slot_id);
#endif

/* External*/

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

#endif
