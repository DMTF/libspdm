/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
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

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP || LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

#define LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK

#define LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK ( \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44 | \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65 | \
        SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87)

libspdm_key_pair_info_t local_key_pair_info[LIBSPDM_MAX_KEY_PAIR_COUNT];

void libspdm_test_provision_key_pair_info(void *spdm_context)
{
    libspdm_data_parameter_t parameter;
    uint8_t i;
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

    libspdm_zero_mem(local_key_pair_info, sizeof(local_key_pair_info));

    /*provisioned key pair info*/

#if (LIBSPDM_RSA_SSA_2048_SUPPORT || LIBSPDM_RSA_PSS_2048_SUPPORT)
    /*key_pair_id 1*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if (LIBSPDM_RSA_SSA_3072_SUPPORT || LIBSPDM_RSA_PSS_3072_SUPPORT)
    /*key_pair_id 2*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if (LIBSPDM_RSA_SSA_4096_SUPPORT || LIBSPDM_RSA_PSS_4096_SUPPORT)
    /*key_pair_id 3*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_rsa, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P256_SUPPORT
    /*key_pair_id 4*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp256);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp256, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P384_SUPPORT
    /*key_pair_id 5*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp384);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp384, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ECDSA_P521_SUPPORT
    /*key_pair_id 6*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp521);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_ecp521, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_SM2_DSA_P256_SUPPORT
    /*key_pair_id 7*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_sm2);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_sm2, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_EDDSA_ED25519_SUPPORT
    /*key_pair_id 8*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ed25519);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_ed25519, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_EDDSA_ED448_SUPPORT
    /*key_pair_id 9*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
    local_key_pair_info[index].current_pqc_asym_algo = 0;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_ed448, local_key_pair_info[index].public_key_info_len);
    index++;
#endif

#if LIBSPDM_ML_DSA_44_SUPPORT
    /*key_pair_id 10 (PQC)*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = 0;
    local_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa44);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa44, sizeof(public_key_info_mldsa44));
    index++;
#endif

#if LIBSPDM_ML_DSA_65_SUPPORT
    /*key_pair_id 11 (PQC)*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = 0;
    local_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa65);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa65, sizeof(public_key_info_mldsa65));
    index++;
#endif

#if LIBSPDM_ML_DSA_87_SUPPORT
    /*key_pair_id 12 (PQC)*/
    local_key_pair_info[index].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    local_key_pair_info[index].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    local_key_pair_info[index].asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].pqc_asym_algo_capabilities = LIBSPDM_TEST_SUPPORTED_KEY_PAIR_PQC_ASYM_ALGO_CAP_MASK;
    local_key_pair_info[index].assoc_cert_slot_mask = 0x03;
    local_key_pair_info[index].current_asym_algo = 0;
    local_key_pair_info[index].current_pqc_asym_algo = SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87;
    local_key_pair_info[index].public_key_info_len = (uint16_t)sizeof(public_key_info_mldsa87);
    libspdm_copy_mem(local_key_pair_info[index].public_key_info,
                     local_key_pair_info[index].public_key_info_len,
                     public_key_info_mldsa87, sizeof(public_key_info_mldsa87));
    index++;
#endif

    /* Multi-key example: for EACH primary key pair above (one per supported algorithm, backing
     * slots 0 and 1), append a SECONDARY key pair of the SAME algorithm that backs slot 4
     * (bundle_responder.certchain4.der / end_responder4.key). This shows two key pairs of one
     * algorithm backing different slots. KeyPairIDs stay contiguous 1..TotalKeyPairs: the primaries
     * are 1..num_primary and their secondaries are num_primary+1..2*num_primary. (SlotID 4 is a
     * NON-CONTIGUOUS slot, since slots 2 and 3 are left empty.) */
    {
        uint8_t num_primary = index;
        for (i = 0; i < num_primary; i++) {
            libspdm_copy_mem(&local_key_pair_info[index], sizeof(local_key_pair_info[index]),
                             &local_key_pair_info[i], sizeof(local_key_pair_info[i]));
            local_key_pair_info[index].assoc_cert_slot_mask = 0x10;
            index++;
        }
    }

    for (i = 0; i < index; i++) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        parameter.additional_data[0] = i + 1;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO, &parameter,
                         &local_key_pair_info[i], sizeof(local_key_pair_info[i]));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS, &parameter, &index,
                     sizeof(index));
}

/* Convert a NEGOTIATE_ALGORITHMS base asymmetric algorithm (Table 113 wire bit, the encoding used
 * by connection_info.algorithm.base_asym_algo) to the key-pair capability encoding (Table 112,
 * the encoding stored in LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO's current_asym_algo). They are
 * different bit layouts. */
static uint32_t libspdm_base_asym_algo_to_key_pair_cap(uint32_t base_asym_algo)
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

void libspdm_set_slot_use_for_key_pairs(void *spdm_context, uint8_t slot_mask)
{
    libspdm_data_parameter_t parameter;
    uint8_t total_key_pairs;
    size_t data_size;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_size = sizeof(total_key_pairs);
    if ((libspdm_get_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS, &parameter,
                          &total_key_pairs, &data_size) != LIBSPDM_STATUS_SUCCESS)) {
        return;
    }

    if (total_key_pairs == 0) {
        return;
    }

    for (int i = 0; i < total_key_pairs; i++) {
        /* Skip the slot 4 secondary key pairs (see above) */
        if ((local_key_pair_info[i].assoc_cert_slot_mask & 0x10) != 0) {
            continue;
        }
        local_key_pair_info[i].assoc_cert_slot_mask = slot_mask;
    }
}

/* Return the device-global KeyPairID (1..TotalKeyPairs) for the key pair that backs (slot_id) under
 * the connection's negotiated algorithm. The PQC bitmap (Table 114) uses the same encoding for both
 * NEGOTIATE_ALGORITHMS and KEY_PAIR_INFO, so it is matched directly; the traditional algorithm is
 * converted to the key-pair capability encoding first.
 *
 * This is how the emu and the signing path obtain a REAL, algorithm-matched, contiguous KeyPairID
 * (per DSP0274, KeyPairIDs are 1..TotalKeyPairs without gaps and each has one fixed algorithm) --
 * the primary key pair of the negotiated algorithm backs slots 0/1 and its secondary backs slot 4.
 * Returns 0 if no matching key pair exists. */
uint8_t libspdm_get_key_pair_id_by_slot(void *spdm_context, uint32_t base_asym_algo,
                                        uint32_t pqc_asym_algo, uint8_t slot_id)
{
    libspdm_data_parameter_t parameter;
    libspdm_key_pair_info_t key_pair_info;
    uint8_t total_key_pairs;
    uint8_t index;
    uint32_t key_pair_asym_algo;
    size_t data_size;

try_again:
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_size = sizeof(total_key_pairs);
    if ((libspdm_get_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS, &parameter,
                          &total_key_pairs, &data_size) != LIBSPDM_STATUS_SUCCESS)) {
        return 0;
    }

    if (total_key_pairs == 0) {
        libspdm_test_provision_key_pair_info(spdm_context);
        goto try_again;
    }

    key_pair_asym_algo = libspdm_base_asym_algo_to_key_pair_cap(base_asym_algo);

    for (index = 0; index < total_key_pairs; index++) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        parameter.additional_data[0] = (uint8_t)(index + 1);
        data_size = sizeof(key_pair_info);
        if (libspdm_get_data(spdm_context, LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO, &parameter,
                             &key_pair_info, &data_size) != LIBSPDM_STATUS_SUCCESS) {
            continue;
        }

        if ((key_pair_info.assoc_cert_slot_mask & (1 << slot_id)) == 0) {
            continue;
        }
        if ((pqc_asym_algo != 0) && (key_pair_info.current_pqc_asym_algo == pqc_asym_algo)) {
            return (uint8_t)(index + 1);
        }
        if ((base_asym_algo != 0) && (key_pair_info.current_asym_algo == key_pair_asym_algo)) {
            return (uint8_t)(index + 1);
        }
    }
    return 0;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP || LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

static bool libspdm_write_key_pair_info_to_nvm(
    uint8_t key_pair_id, const libspdm_key_pair_info_t *key_pair_info,
    bool *need_reset, bool *is_busy)
{
    bool res;
    char file_name[] = "key_pair_info_00";

    /* two-digit KeyPairID, e.g. "key_pair_info_04" */
    file_name[14] = (char)('0' + (key_pair_id / 10));
    file_name[15] = (char)('0' + (key_pair_id % 10));

    res = libspdm_write_output_file(file_name, key_pair_info, sizeof(*key_pair_info));

    return res;
}

bool libspdm_update_local_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset)
{
    libspdm_data_parameter_t parameter;
    libspdm_key_pair_info_t *key_pair_info;
    bool result;
    bool is_busy;

    if ((key_pair_id == 0) || (key_pair_id > LIBSPDM_MAX_KEY_PAIR_COUNT)) {
        return false;
    }

    key_pair_info = &local_key_pair_info[key_pair_id - 1];

    switch (operation) {
    case SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION:
        key_pair_info->current_key_usage = 0;
        key_pair_info->current_asym_algo = 0;
        key_pair_info->current_pqc_asym_algo = 0;
        key_pair_info->assoc_cert_slot_mask = 0;
        break;
    case SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION:
        /* A real device would generate a new cryptographic key pair here. */
        key_pair_info->current_key_usage = desired_key_usage;
        key_pair_info->current_asym_algo = desired_asym_algo;
        key_pair_info->current_pqc_asym_algo = desired_pqc_asym_algo;
        key_pair_info->assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        break;
    case SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION:
        if (desired_key_usage != 0) {
            key_pair_info->current_key_usage = desired_key_usage;
        }
        if (desired_asym_algo != 0) {
            key_pair_info->current_asym_algo = desired_asym_algo;
        }
        if (desired_pqc_asym_algo != 0) {
            key_pair_info->current_pqc_asym_algo = desired_pqc_asym_algo;
        }
        key_pair_info->assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        break;
    default:
        return false;
    }

    is_busy = false;
    result = libspdm_write_key_pair_info_to_nvm(key_pair_id, key_pair_info, need_reset, &is_busy);
    if (!result || is_busy) {
        return false;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    parameter.additional_data[0] = key_pair_id;
    if (libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO, &parameter,
                         key_pair_info, sizeof(*key_pair_info)) != LIBSPDM_STATUS_SUCCESS) {
        return false;
    }

    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
