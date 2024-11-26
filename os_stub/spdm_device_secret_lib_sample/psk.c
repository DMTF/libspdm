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

#define LIBSPDM_CXL_TSP_2ND_SESSION_0_PSK_DATA_STRING "CxlTsp_2ndSess0_Psk"
#define LIBSPDM_CXL_TSP_2ND_SESSION_1_PSK_DATA_STRING "CxlTsp_2ndSess1_Psk"
#define LIBSPDM_CXL_TSP_2ND_SESSION_2_PSK_DATA_STRING "CxlTsp_2ndSess2_Psk"
#define LIBSPDM_CXL_TSP_2ND_SESSION_3_PSK_DATA_STRING "CxlTsp_2ndSess3_Psk"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

uint8_t m_libspdm_my_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_libspdm_my_salt0[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_libspdm_bin_str0[0x11] = {
    0x00, 0x00, /* length - to be filled*/
    /* SPDM_VERSION_1_1_BIN_CONCAT_LABEL */
    0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20,
    /* SPDM_BIN_STR_0_LABEL */
    0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64,
};

uint8_t m_cxl_tsp_2nd_session_psk[CXL_TSP_2ND_SESSION_COUNT][CXL_TSP_2ND_SESSION_KEY_SIZE] = {
    LIBSPDM_CXL_TSP_2ND_SESSION_0_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_1_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_2_PSK_DATA_STRING,
    LIBSPDM_CXL_TSP_2ND_SESSION_3_PSK_DATA_STRING,
};

uint8_t m_cxl_tsp_current_psk_session_index = 0xFF;

bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
        libspdm_set_mem(m_libspdm_my_salt0, sizeof(m_libspdm_my_salt0), 0xff);
    }

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[0];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[0]);
        m_cxl_tsp_current_psk_session_index = 0;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[1];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[1]);
        m_cxl_tsp_current_psk_session_index = 1;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[2];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[2]);
        m_cxl_tsp_current_psk_session_index = 2;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[3];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[3]);
        m_cxl_tsp_current_psk_session_index = 3;
    } else {
        return false;
    }
    printf("[PSK]: ");
    libspdm_dump_hex_str(psk, psk_size);
    printf("\n");

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(handshake_secret, hash_size);

    return result;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t salt1[LIBSPDM_MAX_HASH_SIZE];
    uint8_t master_secret[LIBSPDM_MAX_HASH_SIZE];

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
        m_cxl_tsp_current_psk_session_index = 0xFF;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[0];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[0]);
        m_cxl_tsp_current_psk_session_index = 0;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[1];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[1]);
        m_cxl_tsp_current_psk_session_index = 1;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[2];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[2]);
        m_cxl_tsp_current_psk_session_index = 2;
    } else if ((strcmp((const char *)psk_hint, CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING) == 0) &&
               (psk_hint_size == sizeof(CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING))) {
        psk = m_cxl_tsp_2nd_session_psk[3];
        psk_size = sizeof(m_cxl_tsp_2nd_session_psk[3]);
        m_cxl_tsp_current_psk_session_index = 3;
    } else {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    *(uint16_t *)m_libspdm_bin_str0 = (uint16_t)hash_size;
    /* patch the version*/
    m_libspdm_bin_str0[6] = (char)('0' + ((spdm_version >> 12) & 0xF));
    m_libspdm_bin_str0[8] = (char)('0' + ((spdm_version >> 8) & 0xF));
    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 m_libspdm_bin_str0, sizeof(m_libspdm_bin_str0), salt1,
                                 hash_size);
    libspdm_zero_mem(handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_extract(base_hash_algo, m_libspdm_my_zero_filled_buffer,
                                  hash_size, salt1, hash_size, master_secret, hash_size);
    libspdm_zero_mem(salt1, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, master_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(master_secret, hash_size);

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
