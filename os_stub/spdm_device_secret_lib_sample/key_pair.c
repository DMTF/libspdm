/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
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
typedef struct {
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];
} libspdm_key_pair_info_t;

#ifndef LIBSPDM_MAX_KEY_PAIR_COUNT
#define LIBSPDM_MAX_KEY_PAIR_COUNT 16
#endif

libspdm_key_pair_info_t m_key_pair_info[LIBSPDM_MAX_KEY_PAIR_COUNT];

bool g_need_init_key_pair_info = true;
#endif /*LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

void libspdm_init_key_pair_info(uint8_t total_key_pairs) {
    uint8_t public_key_info_rsa[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                     0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    uint8_t public_key_info_ecp256[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x03, 0x01, 0x07};
    uint8_t public_key_info_ecp384[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    uint8_t public_key_info_ecp521[] = {0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                        0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
    uint8_t public_key_info_sm2[] = {0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
                                     0x02, 0x01, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
                                     0x01, 0x82, 0x2D};
    uint8_t public_key_info_ed25519[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};
    uint8_t public_key_info_ed448[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71};
    uint8_t index;
    /*provisioned key pair info*/

    /*key_pair_id 1*/
    m_key_pair_info[0].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[0].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[0].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[0].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[0].assoc_cert_slot_mask = 0x01;
    m_key_pair_info[0].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048;
    m_key_pair_info[0].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[0].public_key_info, m_key_pair_info[0].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[0].public_key_info_len);

    /*key_pair_id 2*/
    m_key_pair_info[1].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[1].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[1].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[1].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[1].assoc_cert_slot_mask = 0x02;
    m_key_pair_info[1].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072;
    m_key_pair_info[1].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[1].public_key_info, m_key_pair_info[1].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[1].public_key_info_len);

    /*key_pair_id 3*/
    m_key_pair_info[2].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[2].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[2].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[2].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[2].assoc_cert_slot_mask = 0x04;
    m_key_pair_info[2].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096;
    m_key_pair_info[2].public_key_info_len = (uint16_t)sizeof(public_key_info_rsa);
    libspdm_copy_mem(m_key_pair_info[2].public_key_info, m_key_pair_info[2].public_key_info_len,
                     public_key_info_rsa, m_key_pair_info[2].public_key_info_len);

    /*key_pair_id 4*/
    m_key_pair_info[3].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[3].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[3].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[3].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[3].assoc_cert_slot_mask = 0x08;
    m_key_pair_info[3].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256;
    m_key_pair_info[3].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp256);
    libspdm_copy_mem(m_key_pair_info[3].public_key_info, m_key_pair_info[3].public_key_info_len,
                     public_key_info_ecp256, m_key_pair_info[3].public_key_info_len);

    /*key_pair_id 5*/
    m_key_pair_info[4].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[4].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[4].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[4].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[4].assoc_cert_slot_mask = 0x10;
    m_key_pair_info[4].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384;
    m_key_pair_info[4].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp384);
    libspdm_copy_mem(m_key_pair_info[4].public_key_info, m_key_pair_info[4].public_key_info_len,
                     public_key_info_ecp384, m_key_pair_info[4].public_key_info_len);

    /*key_pair_id 6*/
    m_key_pair_info[5].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[5].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[5].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[5].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[5].assoc_cert_slot_mask = 0x20;
    m_key_pair_info[5].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521;
    m_key_pair_info[5].public_key_info_len = (uint16_t)sizeof(public_key_info_ecp521);
    libspdm_copy_mem(m_key_pair_info[5].public_key_info, m_key_pair_info[5].public_key_info_len,
                     public_key_info_ecp521, m_key_pair_info[5].public_key_info_len);

    /*key_pair_id 7*/
    m_key_pair_info[6].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[6].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[6].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[6].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[6].assoc_cert_slot_mask = 0x40;
    m_key_pair_info[6].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2;
    m_key_pair_info[6].public_key_info_len = (uint16_t)sizeof(public_key_info_sm2);
    libspdm_copy_mem(m_key_pair_info[6].public_key_info, m_key_pair_info[6].public_key_info_len,
                     public_key_info_sm2, m_key_pair_info[6].public_key_info_len);

    /*key_pair_id 8*/
    m_key_pair_info[7].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[7].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[7].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[7].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[7].assoc_cert_slot_mask = 0x80;
    m_key_pair_info[7].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519;
    m_key_pair_info[7].public_key_info_len = (uint16_t)sizeof(public_key_info_ed25519);
    libspdm_copy_mem(m_key_pair_info[7].public_key_info, m_key_pair_info[7].public_key_info_len,
                     public_key_info_ed25519, m_key_pair_info[7].public_key_info_len);

    /*key_pair_id 9*/
    m_key_pair_info[8].capabilities = SPDM_KEY_PAIR_CAP_MASK;
    m_key_pair_info[8].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[8].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
    m_key_pair_info[8].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
    m_key_pair_info[8].assoc_cert_slot_mask = 0x00;
    m_key_pair_info[8].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
    m_key_pair_info[8].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
    libspdm_copy_mem(m_key_pair_info[8].public_key_info, m_key_pair_info[8].public_key_info_len,
                     public_key_info_ed448, m_key_pair_info[8].public_key_info_len);

    /*provisioned more key pair info*/
    for (index = 10; index <= total_key_pairs; index++) {
        m_key_pair_info[index - 1].capabilities = SPDM_KEY_PAIR_CAP_MASK;
        m_key_pair_info[index - 1].key_usage_capabilities = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        m_key_pair_info[index - 1].current_key_usage = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE;
        m_key_pair_info[index - 1].asym_algo_capabilities = SPDM_KEY_PAIR_ASYM_ALGO_CAP_MASK;
        m_key_pair_info[index - 1].assoc_cert_slot_mask = 0x00;
        m_key_pair_info[index - 1].current_asym_algo = SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448;
        m_key_pair_info[index - 1].public_key_info_len = (uint16_t)sizeof(public_key_info_ed448);
        libspdm_copy_mem(m_key_pair_info[index - 1].public_key_info,
                         m_key_pair_info[index - 1].public_key_info_len,
                         public_key_info_ed448, m_key_pair_info[index - 1].public_key_info_len);
    }
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
    uint8_t *assoc_cert_slot_mask,
    uint16_t *public_key_info_len,
    uint8_t *public_key_info)
{
    uint8_t total_key_pairs;
    libspdm_data_parameter_t parameter;
    size_t data_return_size;
    libspdm_return_t status;

    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data_return_size = sizeof(uint8_t);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_TOTAL_KEY_PAIRS,
                              &parameter, &total_key_pairs, &data_return_size);
    if (status != LIBSPDM_STATUS_SUCCESS) {
        return false;
    }

    LIBSPDM_ASSERT(total_key_pairs <= LIBSPDM_MAX_KEY_PAIR_COUNT);

    if (g_need_init_key_pair_info) {
        libspdm_init_key_pair_info(total_key_pairs);
        g_need_init_key_pair_info = false;
    }

    /*check*/
    if (key_pair_id > total_key_pairs) {
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
    *assoc_cert_slot_mask = m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask;

    if (public_key_info_len != NULL) {
        *public_key_info_len = m_key_pair_info[key_pair_id - 1].public_key_info_len;
    }
    if (public_key_info != NULL) {
        libspdm_copy_mem(public_key_info, *public_key_info_len,
                         m_key_pair_info[key_pair_id - 1].public_key_info, *public_key_info_len);

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
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset)
{
    bool result;
    libspdm_cached_key_pair_info_data_t *cached_key_pair_info;
    libspdm_cached_key_pair_info_data_t current_key_pair_info;
    size_t cached_key_pair_info_len;


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
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
                m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask =
                    desired_assoc_cert_slot_mask;
            } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
                if (desired_key_usage != 0) {
                    m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
                }
                if (desired_asym_algo != 0) {
                    m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
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
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = 0;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
            m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else if (operation == SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION) {
            if (desired_key_usage != 0) {
                m_key_pair_info[key_pair_id - 1].current_key_usage = desired_key_usage;
            }
            if (desired_asym_algo != 0) {
                m_key_pair_info[key_pair_id - 1].current_asym_algo = desired_asym_algo;
            }
            m_key_pair_info[key_pair_id - 1].assoc_cert_slot_mask = desired_assoc_cert_slot_mask;
        } else {
            return false;
        }

        return true;
    }
}
#endif /* #if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */
