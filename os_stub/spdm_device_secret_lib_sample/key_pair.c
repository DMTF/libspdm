/**
 *  Copyright Notice:
 *  Copyright 2024-2025 DMTF. All rights reserved.
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
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

#define LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK

#define LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK ( \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44 | \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65 | \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87)

typedef struct {
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];
} libspdm_key_pair_info_t;

#define LIBSPDM_MAX_KEY_PAIR_COUNT (9 + 3)

libspdm_key_pair_info_t m_key_pair_info[LIBSPDM_MAX_KEY_PAIR_COUNT];

uint8_t m_total_key_pair_count = 0;

void libspdm_init_key_pair_info() {
#if (LIBSPDM_RSA_SSA_SUPPORT || LIBSPDM_RSA_PSS_SUPPORT)
    uint8_t public_key_info_rsa[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                     0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
#endif
#if LIBSPDM_ECDSA_P256_SUPPORT
    uint8_t public_key_info_ecp256[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x03, 0x01, 0x07};
#endif
#if LIBSPDM_ECDSA_P384_SUPPORT
    uint8_t public_key_info_ecp384[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
#endif
#if LIBSPDM_ECDSA_P521_SUPPORT
    uint8_t public_key_info_ecp521[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
#endif
#if LIBSPDM_SM2_DSA_P256_SUPPORT
    uint8_t public_key_info_sm2[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                     0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
                                     0x01, 0x82, 0x2D};
#endif
#if LIBSPDM_EDDSA_ED25519_SUPPORT
    uint8_t public_key_info_ed25519[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};
#endif
#if LIBSPDM_EDDSA_ED448_SUPPORT
    uint8_t public_key_info_ed448[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71};
#endif
#if LIBSPDM_ML_DSA_44_SUPPORT
    uint8_t public_key_info_mldsa44[] = {0x30, 0x0A, 0x06, 0x09,
                                         /* 2.16.840.1.101.3.4.3.17 */
                                         0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11};
#endif
#if LIBSPDM_ML_DSA_65_SUPPORT
    uint8_t public_key_info_mldsa65[] = {0x30, 0x0A, 0x06, 0x09,
                                         /* 2.16.840.1.101.3.4.3.18 */
                                         0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
#endif
#if LIBSPDM_ML_DSA_87_SUPPORT
    uint8_t public_key_info_mldsa87[] = {0x30, 0x0A, 0x06, 0x09,
                                         /* 2.16.840.1.101.3.4.3.19 */
                                         0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13};
#endif
    uint8_t index = 0;
    /*provisioned key pair info*/

#if (LIBSPDM_RSA_SSA_2048_SUPPORT || LIBSPDM_RSA_PSS_2048_SUPPORT)
    /*key_pair_id 1*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x01;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if (LIBSPDM_RSA_SSA_3072_SUPPORT || LIBSPDM_RSA_PSS_3072_SUPPORT)
    /*key_pair_id 2*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x02;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if (LIBSPDM_RSA_SSA_4096_SUPPORT || LIBSPDM_RSA_PSS_4096_SUPPORT)
    /*key_pair_id 3*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x04;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P256_SUPPORT
    /*key_pair_id 4*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x08;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp256);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp256, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P384_SUPPORT
    /*key_pair_id 5*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x10;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp384);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp384, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P521_SUPPORT
    /*key_pair_id 6*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x20;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp521);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp521, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_SM2_DSA_P256_SUPPORT
    /*key_pair_id 7*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x40;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_sm2);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_sm2, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_EDDSA_ED25519_SUPPORT
    /*key_pair_id 8*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x80;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ed25519);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_ed25519, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_EDDSA_ED448_SUPPORT
    /*key_pair_id 9*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
    m_key_pair_info[index].current_pqc_asym_algo = 0;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info,
                     m_key_pair_info[index].public_key_info_len,
                     public_key_info_ed448, m_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ML_DSA_44_SUPPORT
    /*key_pair_id 10 (PQC)*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[index].current_asym_algo = 0;
    m_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa44);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info, m_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa44, sizeof(public_key_info_mldsa44));
    index++;
#endif

#if LIBSPDM_ML_DSA_65_SUPPORT
    /*key_pair_id 11 (PQC)*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[index].current_asym_algo = 0;
    m_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa65);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info, m_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa65, sizeof(public_key_info_mldsa65));
    index++;
#endif

#if LIBSPDM_ML_DSA_87_SUPPORT
    /*key_pair_id 12 (PQC)*/
    m_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[index].asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[index].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[index].current_asym_algo = 0;
    m_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87;
    m_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa87);
    libspdm_copy_mem(m_key_pair_info[index].public_key_info, m_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa87, sizeof(public_key_info_mldsa87));
    index++;
#endif

    m_total_key_pair_count = index;
}

uint8_t libspdm_read_total_key_pairs (void *spdm_context)
{
    if (m_total_key_pair_count == 0) {
        libspdm_init_key_pair_info();
    }
    return m_total_key_pair_count;
}

/**
 * read the key pair info of the key_pair_id.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  key_pair_id                Indicate which key pair ID's information to retrieve.
 *
 * @param  capabilities               Indicate the capabilities of the requested key pairs.
 * @param  key_usage_capabilities     Indicate the key usages the responder allows.
 * @param  current_key_usage          Indicate the currently configured key usage for the requested key pairs ID.
 * @param  asym_algo_capabilities     Indicate the asymmetric algorithms the Responder supports for this key pair ID.
 * @param  current_asym_algo          Indicate the currently configured asymmetric algorithm for this key pair ID.
 * @param  assoc_cert_slot_mask       This field is a bit mask representing the currently associated certificate slots.
 * @param  public_key_info_len        On input, indicate the size in bytes of the destination buffer to store.
 *                                    On output, indicate the size in bytes of the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 * @param  public_key_info            A pointer to a destination buffer to store the public_key_info.
 *                                    It can be NULL, if public_key_info is not required.
 *
 * @retval true  get key pair info successfully.
 * @retval false get key pair info failed.
 **/
bool libspdm_read_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint16_t *capabilities,
    uint16_t *key_usage_capabilities,
    uint16_t *current_key_usage,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint32_t *pqc_asym_algo_capabilities,
    uint32_t *current_pqc_asym_algo,
    uint8_t *assoc_cert_slot_mask,
    uint16_t *public_key_info_len,
    uint8_t *public_key_info)
{
    /*check*/
    if (key_pair_id > libspdm_read_total_key_pairs(spdm_context)) {
        return false;
    }

    if (public_key_info_len != NULL) {
        if (*public_key_info_len < m_key_pair_info[key_pair_id - 1].public_key_info_len) {
            return false;
        }
    }

    /*output*/
    *capabilities = m_key_pair_info[key_pair_id - 1].capabilities;
    *key_usage_capabilities = m_key_pair_info[key_pair_id - 1].key_usage_capabilities;
    *current_key_usage = m_key_pair_info[key_pair_id - 1].current_key_usage;
    *asym_algo_capabilities = m_key_pair_info[key_pair_id - 1].asym_algo_capabilities;
    *current_asym_algo = m_key_pair_info[key_pair_id - 1].current_asym_algo;
    if (pqc_asym_algo_capabilities != NULL) {
        *pqc_asym_algo_capabilities = m_key_pair_info[key_pair_id - 1].pqc_asym_algo_capabilities;
    }
    if (current_pqc_asym_algo != NULL) {
        *current_pqc_asym_algo = m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo;
    }
    *assoc_cert_slot_mask = m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask;

    if (public_key_info_len != NULL) {
        *public_key_info_len = m_key_pair_info[key_pair_id - 1].public_key_info_len;
        if (public_key_info != NULL) {
            libspdm_copy_mem(public_key_info, *public_key_info_len,
                             m_key_pair_info[key_pair_id - 1].public_key_info, *public_key_info_len);
        }
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

typedef struct
{
    uint8_t key_pair_id;
    uint8_t operation;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint32_t desired_pqc_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;
} libspdm_cached_key_pair_info_data_t;


bool libspdm_read_cached_last_set_key_pair_info_request(uint8_t **last_set_key_pair_info_request,
                                                        size_t *last_set_key_pair_info_request_len)
{
    bool res;
    char file[] = "cached_last_set_key_pair_info_request";

    res = libspdm_read_input_file(file, (void **)last_set_key_pair_info_request,
                                  last_set_key_pair_info_request_len);

    return res;
}

bool libspdm_cache_last_set_key_pair_info_request(const uint8_t *last_set_key_pair_info_request,
                                                  size_t last_set_key_pair_info_request_len)
{
    bool res;
    char file[] = "cached_last_set_key_pair_info_request";

    res = libspdm_write_output_file(file, last_set_key_pair_info_request,
                                    last_set_key_pair_info_request_len);

    return res;
}

bool libspdm_write_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset)
{
    bool result;
    libspdm_cached_key_pair_info_data_t *cached_key_pair_info;
    libspdm_cached_key_pair_info_data_t current_key_pair_info;
    size_t cached_key_pair_info_len;

    /*check*/
    if (key_pair_id > libspdm_read_total_key_pairs(spdm_context)) {
        return false;
    }

    cached_key_pair_info_len = 0;
    if (*need_reset) {
        result = libspdm_read_cached_last_set_key_pair_info_request(
            (uint8_t **)&cached_key_pair_info,
            &cached_key_pair_info_len);

        if ((result) &&
            (cached_key_pair_info_len == sizeof(libspdm_cached_key_pair_info_data_t)) &&
            (cached_key_pair_info->operation == operation) &&
            (cached_key_pair_info->key_pair_id == key_pair_id) &&
            (cached_key_pair_info->desired_key_usage == desired_key_usage) &&
            (cached_key_pair_info->desired_asym_algo == desired_asym_algo) &&
            (cached_key_pair_info->desired_assoc_cert_slot_mask == desired_assoc_cert_slot_mask)) {
            if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = 0;
                m_key_pair_info[key_pair_id - 1].current_asym_algo = 0;
                m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = 0;
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
                m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = desired_pqc_asym_algo;
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask =
                    desired_assoc_cert_slot_mask;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
                if (desired_key_usage != 0) {
                    m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                }
                if (desired_asym_algo != 0) {
                    m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
                }
                if (desired_pqc_asym_algo != 0) {
                    m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = desired_pqc_asym_algo;
                }
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask =
                    desired_assoc_cert_slot_mask;
            } else {
                return false;
            }

            /*device don't need reset this time*/
            *need_reset = false;
            free(cached_key_pair_info);
            return true;
        } else {
            if (cached_key_pair_info != NULL) {
                free(cached_key_pair_info);
            }

            current_key_pair_info.operation = operation;
            current_key_pair_info.key_pair_id = key_pair_id;
            current_key_pair_info.desired_key_usage = desired_key_usage;
            current_key_pair_info.desired_asym_algo = desired_asym_algo;
            current_key_pair_info.desired_pqc_asym_algo = desired_pqc_asym_algo;
            current_key_pair_info.desired_assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
            /*device need reset this time: cache the last_set_key_pair_info_request */
            result = libspdm_cache_last_set_key_pair_info_request(
                (const uint8_t *)&current_key_pair_info,
                sizeof(libspdm_cached_key_pair_info_data_t));
            if (!result) {
                return result;
            }

            /*device need reset this time*/
            *need_reset = true;
            return true;
        }
    } else {
        if (operation == SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) {
            m_key_pair_info[key_pair_id - 1].current_key_usage = 0;
            m_key_pair_info[key_pair_id - 1].current_asym_algo = 0;
            m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = 0;
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
            m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = desired_pqc_asym_algo;
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
            if (desired_key_usage != 0) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            }
            if (desired_asym_algo != 0) {
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            }
            if (desired_pqc_asym_algo != 0) {
                m_key_pair_info[key_pair_id - 1].current_pqc_asym_algo = desired_pqc_asym_algo;
            }
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else {
            return false;
        }

        return true;
    }
}
#endif /* #if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
