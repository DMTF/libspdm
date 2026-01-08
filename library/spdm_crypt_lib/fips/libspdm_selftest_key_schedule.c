/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

bool libspdm_fips_selftest_key_schedule_dhe_14(void *fips_selftest_context)
{
    const uint8_t dhe_shared_secret[] = {
        0xa9, 0x1d, 0xd8, 0xce, 0x6f, 0x33, 0x7c, 0x7d, 0x69, 0xec, 0x28, 0x38,
        0x2b, 0xdd, 0x20, 0x5d, 0x2d, 0x5c, 0xc9, 0x10, 0xd7, 0x7c, 0x1c, 0xf0,
        0xed, 0xd9, 0xe9, 0x8f, 0x4f, 0xac, 0x40, 0xda
    };

    const uint8_t th1_hash_data[] = {
        0x17, 0x1f, 0x69, 0xb6, 0x12, 0xd2, 0x43, 0x53, 0xb1, 0xb4, 0xfc, 0x0a,
        0x28, 0x2a, 0xc2, 0xa2, 0x60, 0xb3, 0x68, 0x6b, 0x1c, 0xa1, 0x04, 0x78,
        0x1b, 0x57, 0x97, 0x18, 0x0e, 0x74, 0x2c, 0x59
    };

    const uint8_t th2_hash_data[] = {
        0x0f, 0x65, 0x44, 0xc5, 0xd5, 0xba, 0xc2, 0x77, 0x5d, 0x9e, 0xf4, 0xae,
        0x0b, 0xcd, 0xd3, 0xc9, 0x14, 0xfd, 0xd0, 0x86, 0x33, 0xb2, 0xc1, 0xc9,
        0xc5, 0x14, 0x4e, 0x55, 0xe4, 0x7e, 0xd2, 0xff
    };

    const uint8_t expected_request_handshake_secret[] = {
        0x2f, 0x4a, 0x23, 0x36, 0x53, 0xd6, 0xba, 0x27, 0x7f, 0x45, 0xa6, 0xef,
        0xcd, 0xd1, 0x6f, 0x4d, 0xd1, 0xa8, 0x8a, 0xa2, 0xa1, 0x97, 0x42, 0xd0,
        0xe4, 0xc5, 0x22, 0xf5, 0x8a, 0xe2, 0x57, 0x69
    };

    const uint8_t expected_response_handshake_secret[] = {
        0xb9, 0x12, 0xe8, 0x16, 0xa0, 0x90, 0x9a, 0x6a, 0xb5, 0x73, 0xfd, 0xbe,
        0x8a, 0x6d, 0xb6, 0x85, 0x5b, 0xd8, 0x9b, 0x53, 0xbf, 0x4a, 0x2f, 0x24,
        0xc1, 0xef, 0x91, 0x00, 0x7f, 0xca, 0x03, 0xba
    };

    const uint8_t expected_request_data_secret[] = {
        0x73, 0xb6, 0x9e, 0xfa, 0x7c, 0x7b, 0x3e, 0x68, 0xda, 0x30, 0x18, 0xff,
        0x41, 0x4a, 0x20, 0x66, 0xe8, 0x28, 0xb8, 0xff, 0x72, 0x73, 0xcc, 0x66,
        0x43, 0xc7, 0x99, 0x5b, 0x74, 0x84, 0x5e, 0x63
    };

    const uint8_t expected_response_data_secret[] = {
        0x25, 0x67, 0xa8, 0x94, 0x51, 0x8a, 0x5b, 0x48, 0xeb, 0x6d, 0xef, 0x76,
        0xc5, 0xe7, 0xc8, 0xb6, 0xb6, 0xd5, 0x2d, 0x17, 0x3e, 0x42, 0x07, 0xbb,
        0xcb, 0xfd, 0x8f, 0x52, 0xcd, 0xd3, 0x46, 0x0a
    };

    const uint8_t expected_export_master_secret[] = {
        0x9d, 0x32, 0xf7, 0xb4, 0x43, 0x73, 0x79, 0x81, 0x7a, 0x0f, 0xea, 0xaa,
        0xb2, 0x38, 0x2c, 0x28, 0x06, 0x82, 0x3b, 0x65, 0x83, 0xe8, 0x26, 0x74,
        0x03, 0xb7, 0x7f, 0xaa, 0x91, 0x14, 0xcc, 0x8e
    };

    uint8_t handshake_secret[32];
    size_t handshake_secret_size = sizeof(handshake_secret);
    uint8_t request_handshake_secret[32];
    size_t request_handshake_secret_size = sizeof(request_handshake_secret);
    uint8_t response_handshake_secret[32];
    size_t response_handshake_secret_size = sizeof(response_handshake_secret);
    uint8_t master_secret[32];
    size_t master_secret_size = sizeof(master_secret);
    uint8_t request_data_secret[32];
    size_t request_data_secret_size = sizeof(request_data_secret);
    uint8_t response_data_secret[32];
    size_t response_data_secret_size = sizeof(response_data_secret);
    uint8_t export_master_secret[32];
    size_t export_master_secret_size = sizeof(export_master_secret);
    bool result = true;
    uint32_t base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    size_t hash_size = libspdm_get_hash_size(base_hash_algo);

    if (hash_size != sizeof(expected_request_handshake_secret)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_handshake_key (
        SPDM_MESSAGE_VERSION_14 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        dhe_shared_secret, sizeof(dhe_shared_secret),
        false,
        NULL, 0, false,
        base_hash_algo,
        th1_hash_data,
        handshake_secret, &handshake_secret_size,
        request_handshake_secret, &request_handshake_secret_size,
        response_handshake_secret, &response_handshake_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_handshake_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_handshake_secret,
        expected_request_handshake_secret, sizeof(expected_request_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_handshake_secret,
        expected_response_handshake_secret, sizeof(expected_response_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_data_key (
        SPDM_MESSAGE_VERSION_14 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        handshake_secret, handshake_secret_size,
        NULL, 0, false,
        base_hash_algo,
        th2_hash_data,
        master_secret, &master_secret_size,
        request_data_secret, &request_data_secret_size,
        response_data_secret, &response_data_secret_size,
        export_master_secret, &export_master_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_data_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_data_secret,
        expected_request_data_secret, sizeof(expected_request_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_data_secret,
        expected_response_data_secret, sizeof(expected_response_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        export_master_secret,
        expected_export_master_secret, sizeof(expected_export_master_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    return true;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
bool libspdm_fips_selftest_key_schedule_psk_13(void *fips_selftest_context)
{
    const uint8_t psk[] = {
        0x75, 0x36, 0xbb, 0x7e, 0xca, 0x2d, 0xd7, 0x2a, 0x6d, 0xfa, 0x23, 0xdd,
        0x47, 0xe4, 0x9e, 0xad, 0xb3, 0x89, 0xa2, 0xb4, 0xc2, 0x37, 0xe4, 0x63,
        0xe0, 0x87, 0xc1, 0xac, 0x94, 0x85, 0x16, 0xca
    };

    const uint8_t th1_hash_data[] = {
        0xa7, 0x61, 0xbc, 0x94, 0xd4, 0x6a, 0x17, 0x1c, 0xa7, 0x60, 0x72, 0x7f,
        0x0a, 0x63, 0xbd, 0x22, 0x6f, 0x2d, 0xe5, 0x18, 0x5f, 0x95, 0x44, 0xc8,
        0x93, 0x16, 0xa6, 0xd7, 0xec, 0x2f, 0x2b, 0x68
    };

    const uint8_t th2_hash_data[] = {
        0x0b, 0xff, 0x41, 0x3c, 0xc0, 0xd0, 0x88, 0xcb, 0xf5, 0xf6, 0x2c, 0x58,
        0xc1, 0xa7, 0xbd, 0xa9, 0x45, 0x54, 0x9b, 0x8e, 0x99, 0x7f, 0x50, 0x87,
        0x06, 0xdb, 0x9d, 0x72, 0x88, 0x5a, 0xc1, 0xae
    };

    const uint8_t expected_request_handshake_secret[] = {
        0x29, 0xfb, 0xde, 0x0e, 0xe1, 0xb6, 0x1c, 0x00, 0x3c, 0xbd, 0x14, 0xa4,
        0x21, 0x4e, 0x7e, 0xed, 0xc8, 0xc0, 0xed, 0x4e, 0x1e, 0x2c, 0xad, 0x1c,
        0x5b, 0x9d, 0x89, 0xb3, 0x14, 0xa7, 0xe3, 0x7d
    };

    const uint8_t expected_response_handshake_secret[] = {
        0x09, 0xea, 0x6a, 0x31, 0xbd, 0x85, 0x2f, 0xfe, 0x02, 0x48, 0x33, 0x03,
        0xeb, 0x24, 0x2b, 0x77, 0xb3, 0x54, 0xe7, 0xee, 0xe1, 0x20, 0xe6, 0x76,
        0x41, 0xe2, 0x77, 0x49, 0xf2, 0xcc, 0x19, 0xb4
    };

    const uint8_t expected_request_data_secret[] = {
        0x17, 0xec, 0x63, 0xa8, 0xa4, 0x23, 0x73, 0x93, 0xf9, 0xd2, 0x9e, 0x76,
        0x81, 0x02, 0xda, 0xaa, 0xde, 0xe5, 0xb7, 0x55, 0x36, 0x09, 0x14, 0x6a,
        0x10, 0xd1, 0xcd, 0x0b, 0xd0, 0x30, 0x2d, 0xcd
    };

    const uint8_t expected_response_data_secret[] = {
        0x99, 0xa2, 0x8e, 0x99, 0xff, 0x9c, 0x2d, 0xc9, 0xfe, 0xe8, 0x34, 0xed,
        0x83, 0x63, 0x56, 0x62, 0x1a, 0xe0, 0xe6, 0x75, 0xb8, 0x2f, 0x5b, 0x9f,
        0xb3, 0x2b, 0x3d, 0x85, 0x5f, 0xf8, 0xd3, 0x0f
    };

    const uint8_t expected_export_master_secret[] = {
        0x4d, 0x3c, 0x03, 0x78, 0x6a, 0xcd, 0x8d, 0xab, 0x1a, 0x53, 0xde, 0x0e,
        0xb2, 0x67, 0xd7, 0x1f, 0x12, 0xd2, 0xa7, 0xb0, 0x42, 0xa7, 0x70, 0x05,
        0x92, 0x67, 0xa2, 0x19, 0xa1, 0xc0, 0xc9, 0x27
    };

    uint8_t handshake_secret[32];
    size_t handshake_secret_size = sizeof(handshake_secret);
    uint8_t request_handshake_secret[32];
    size_t request_handshake_secret_size = sizeof(request_handshake_secret);
    uint8_t response_handshake_secret[32];
    size_t response_handshake_secret_size = sizeof(response_handshake_secret);
    uint8_t master_secret[32];
    size_t master_secret_size = sizeof(master_secret);
    uint8_t request_data_secret[32];
    size_t request_data_secret_size = sizeof(request_data_secret);
    uint8_t response_data_secret[32];
    size_t response_data_secret_size = sizeof(response_data_secret);
    uint8_t export_master_secret[32];
    size_t export_master_secret_size = sizeof(export_master_secret);
    bool result = true;
    uint32_t base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    size_t hash_size = libspdm_get_hash_size(base_hash_algo);

    if (hash_size != sizeof(expected_request_handshake_secret)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_handshake_key (
        SPDM_MESSAGE_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        psk, sizeof(psk),
        true,
        NULL, 0, false,
        base_hash_algo,
        th1_hash_data,
        handshake_secret, &handshake_secret_size,
        request_handshake_secret, &request_handshake_secret_size,
        response_handshake_secret, &response_handshake_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_handshake_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_handshake_secret,
        expected_request_handshake_secret, sizeof(expected_request_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_handshake_secret,
        expected_response_handshake_secret, sizeof(expected_response_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_data_key (
        SPDM_MESSAGE_VERSION_13 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        handshake_secret, sizeof(handshake_secret),
        NULL, 0, false,
        base_hash_algo,
        th2_hash_data,
        master_secret, &master_secret_size,
        request_data_secret, &request_data_secret_size,
        response_data_secret, &response_data_secret_size,
        export_master_secret, &export_master_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_data_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_data_secret,
        expected_request_data_secret, sizeof(expected_request_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_data_secret,
        expected_response_data_secret, sizeof(expected_response_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        export_master_secret,
        expected_export_master_secret, sizeof(expected_export_master_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    return true;
}

bool libspdm_fips_selftest_key_schedule_psk_12(void *fips_selftest_context)
{
    const uint8_t psk[] = {
        0xce, 0x96, 0xa3, 0xf0, 0x08, 0x3d, 0xbd, 0xd3, 0x5b, 0x21, 0xe7, 0x0c,
        0xa7, 0xe5, 0xc3, 0x58, 0x19, 0xd9, 0x58, 0xf5, 0x3e, 0xa3, 0x18, 0xe3,
        0xce, 0x36, 0x5e, 0x87, 0xe6, 0xd1, 0x1f, 0x41
    };

    const uint8_t th1_hash_data[] = {
        0x3f, 0xde, 0x2d, 0x21, 0xc9, 0x13, 0x76, 0xfd, 0x59, 0x72, 0x87, 0x3f,
        0x9f, 0xad, 0x1b, 0xb4, 0x20, 0x5f, 0xca, 0x05, 0xbd, 0x7f, 0xb9, 0xc2,
        0xcc, 0xd7, 0xb2, 0x68, 0x35, 0x2f, 0xb7, 0x1e
    };

    const uint8_t th2_hash_data[] = {
        0x94, 0xab, 0x0e, 0x9f, 0xf2, 0x37, 0xd5, 0x44, 0x96, 0x8e, 0xf6, 0xf5,
        0xd5, 0x53, 0x1c, 0x5d, 0x09, 0x55, 0x64, 0x68, 0x53, 0xe5, 0x18, 0xeb,
        0xa5, 0xb0, 0xa4, 0x29, 0x3e, 0x1f, 0xd4, 0x81
    };

    const uint8_t expected_request_handshake_secret[] = {
        0x47, 0xff, 0x68, 0xed, 0x2a, 0xe2, 0xb8, 0x3d, 0x7c, 0xdd, 0x4e, 0x0c,
        0x6f, 0xc7, 0x8b, 0x34, 0xb3, 0x6d, 0xe7, 0x64, 0x6f, 0xfa, 0x4d, 0x3c,
        0xd8, 0xfb, 0x49, 0x49, 0x8e, 0x40, 0x44, 0x4f
    };

    const uint8_t expected_response_handshake_secret[] = {
        0x6b, 0x46, 0x99, 0x9e, 0x76, 0xc4, 0xd2, 0x2c, 0x40, 0x2d, 0x7e, 0xaa,
        0xce, 0x9a, 0xdc, 0x1a, 0xbc, 0x73, 0x0a, 0xa2, 0xf4, 0x5d, 0x45, 0x19,
        0x1b, 0x16, 0xac, 0xad, 0x55, 0x2c, 0x2b, 0xc6
    };

    const uint8_t expected_request_data_secret[] = {
        0x03, 0x31, 0x68, 0xfc, 0xe6, 0x9d, 0x68, 0xb4, 0x9a, 0x79, 0x58, 0xfd,
        0x17, 0x68, 0x17, 0xb4, 0x88, 0x1c, 0x24, 0xc1, 0x10, 0x44, 0xb7, 0xd7,
        0xc4, 0x4c, 0xfe, 0xcc, 0x02, 0x6b, 0x7e, 0x97
    };

    const uint8_t expected_response_data_secret[] = {
        0x6f, 0x3a, 0x37, 0x35, 0x31, 0x68, 0x97, 0x67, 0x78, 0x1c, 0xe1, 0xac,
        0xc8, 0xf7, 0x3c, 0x00, 0x0e, 0x11, 0xef, 0x6a, 0xbd, 0xcd, 0xdc, 0xe2,
        0x33, 0xaa, 0xad, 0xd8, 0x3f, 0x00, 0x2c, 0x8e
    };

    const uint8_t expected_export_master_secret[] = {
        0xb4, 0xfd, 0x59, 0x89, 0x0f, 0xdf, 0x97, 0x40, 0x48, 0xe1, 0x2a, 0x1e,
        0x9b, 0x52, 0xa0, 0x6f, 0xec, 0xe8, 0xf6, 0xc4, 0xe3, 0xff, 0x4c, 0xfe,
        0x93, 0x3c, 0x6a, 0xd8, 0xde, 0x40, 0xa7, 0xa1
    };

    uint8_t handshake_secret[32];
    size_t handshake_secret_size = sizeof(handshake_secret);
    uint8_t request_handshake_secret[32];
    size_t request_handshake_secret_size = sizeof(request_handshake_secret);
    uint8_t response_handshake_secret[32];
    size_t response_handshake_secret_size = sizeof(response_handshake_secret);
    uint8_t master_secret[32];
    size_t master_secret_size = sizeof(master_secret);
    uint8_t request_data_secret[32];
    size_t request_data_secret_size = sizeof(request_data_secret);
    uint8_t response_data_secret[32];
    size_t response_data_secret_size = sizeof(response_data_secret);
    uint8_t export_master_secret[32];
    size_t export_master_secret_size = sizeof(export_master_secret);
    bool result = true;
    uint32_t base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    size_t hash_size = libspdm_get_hash_size(base_hash_algo);

    if (hash_size != sizeof(expected_request_handshake_secret)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule DHE+SPDM 1.4 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_handshake_key (
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        psk, sizeof(psk),
        true,
        NULL, 0, false,
        base_hash_algo,
        th1_hash_data,
        handshake_secret, &handshake_secret_size,
        request_handshake_secret, &request_handshake_secret_size,
        response_handshake_secret, &response_handshake_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_handshake_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_handshake_secret,
        expected_request_handshake_secret, sizeof(expected_request_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_handshake_secret,
        expected_response_handshake_secret, sizeof(expected_response_handshake_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    result = libspdm_generate_data_key (
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        handshake_secret, sizeof(handshake_secret),
        NULL, 0, false,
        base_hash_algo,
        th2_hash_data,
        master_secret, &master_secret_size,
        request_data_secret, &request_data_secret_size,
        response_data_secret, &response_data_secret_size,
        export_master_secret, &export_master_secret_size);

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_data_key failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        request_data_secret,
        expected_request_data_secret, sizeof(expected_request_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        response_data_secret,
        expected_response_data_secret, sizeof(expected_response_data_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    if (!libspdm_consttime_is_mem_equal(
        export_master_secret,
        expected_export_master_secret, sizeof(expected_export_master_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SPDM Key Schedule PSK+SPDM 1.3 KAT failed \n"));
        return false;
    }

    return true;
}
#endif

/**
 * spdm key schedule self_test
 **/
bool libspdm_fips_selftest_key_schedule(void *fips_selftest_context)
{
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_KEY_SCHEDULE) != 0) {
        return true;
    }

    result = libspdm_fips_selftest_key_schedule_dhe_14(fips_selftest_context);
    if (!result) {
        goto update;
    }

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    result = libspdm_fips_selftest_key_schedule_psk_13(fips_selftest_context);
    if (!result) {
        goto update;
    }

    result = libspdm_fips_selftest_key_schedule_psk_12(fips_selftest_context);
    if (!result) {
        goto update;
    }
#endif


update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_KEY_SCHEDULE;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_KEY_SCHEDULE;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_KEY_SCHEDULE;
    }


    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
