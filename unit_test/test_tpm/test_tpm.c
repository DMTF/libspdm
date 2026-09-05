/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_crypt_ext_lib.h"
#include "cryptlib_openssl/tpm/tpm_internal.h"

static void libspdm_test_tpm_read_pcr_buffer_too_small(void **state)
{
    bool status;
    size_t buffer_size;
    uint8_t buffer[32];
    uint8_t original_buffer[sizeof(buffer)];

    libspdm_set_mem(buffer, sizeof(buffer), 0x5a);
    libspdm_copy_mem(original_buffer, sizeof(original_buffer), buffer, sizeof(buffer));

    buffer_size = sizeof(buffer) - 1;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        1, buffer, &buffer_size);

    assert_false(status);
    assert_int_equal(buffer_size, 32);
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));

    buffer_size = 0;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
        1, buffer, &buffer_size);

    assert_false(status);
    assert_int_equal(buffer_size, 64);
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));
}

static void libspdm_test_tpm_copy_nv_chunk(void **state)
{
    bool status;
    size_t offset;
    uint8_t buffer[8];
    uint8_t original_buffer[sizeof(buffer)];
    const uint8_t first_chunk[] = { 1, 2, 3, 4 };
    const uint8_t second_chunk[] = { 5, 6, 7, 8 };

    libspdm_zero_mem(buffer, sizeof(buffer));
    offset = 0;
    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       first_chunk, sizeof(first_chunk),
                                       sizeof(first_chunk));
    assert_true(status);
    assert_int_equal(offset, sizeof(first_chunk));
    assert_memory_equal(buffer, first_chunk, sizeof(first_chunk));

    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       second_chunk, sizeof(second_chunk),
                                       sizeof(second_chunk));
    assert_true(status);
    assert_int_equal(offset, sizeof(buffer));
    assert_memory_equal(buffer + sizeof(first_chunk), second_chunk,
                        sizeof(second_chunk));

    libspdm_copy_mem(original_buffer, sizeof(original_buffer), buffer, sizeof(buffer));

    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       NULL, 1, 1);
    assert_false(status);
    assert_int_equal(offset, sizeof(buffer));
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));

    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       second_chunk, 0, sizeof(second_chunk));
    assert_false(status);
    assert_int_equal(offset, sizeof(buffer));
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));

    offset = 4;
    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       second_chunk, sizeof(second_chunk), 3);
    assert_false(status);
    assert_int_equal(offset, 4);
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));

    offset = 5;
    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       second_chunk, sizeof(second_chunk),
                                       sizeof(second_chunk));
    assert_false(status);
    assert_int_equal(offset, 5);
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));

    offset = sizeof(buffer) + 1;
    status = libspdm_tpm_copy_nv_chunk(buffer, sizeof(buffer), &offset,
                                       second_chunk, 1, 1);
    assert_false(status);
    assert_int_equal(offset, sizeof(buffer) + 1);
    assert_memory_equal(buffer, original_buffer, sizeof(buffer));
}

int main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_tpm_read_pcr_buffer_too_small),
        cmocka_unit_test(libspdm_test_tpm_copy_nv_chunk),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}
