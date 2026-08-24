/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"

/**
 * Test 1: Test support functions.
 **/
static void libspdm_test_common_context_data_case1(void **state)
{
    assert_int_equal(0x0001020304050607, libspdm_byte_swap_64(UINT64_C(0x0706050403020100)));
}

/**
 * Test 2: Test libspdm_read_uint16 and libspdm_write_uint16.
 **/
static void libspdm_test_common_read_write_uint16(void **state)
{
    uint8_t buffer[2];
    uint16_t value;

    value = libspdm_read_uint16((const uint8_t *)"\x01\x02");
    assert_int_equal(value, 0x0201);

    libspdm_write_uint16(buffer, 0x0201);
    assert_memory_equal(buffer, "\x01\x02", sizeof(buffer));

    libspdm_write_uint16(buffer, 0xFFFF);
    assert_int_equal(libspdm_read_uint16(buffer), 0xFFFF);

    libspdm_write_uint16(buffer, 0x0000);
    assert_int_equal(libspdm_read_uint16(buffer), 0x0000);
}

/**
 * Test 3: Test libspdm_read_uint24 and libspdm_write_uint24.
 **/
static void libspdm_test_common_read_write_uint24(void **state)
{
    uint8_t buffer[3];
    uint32_t value;

    value = libspdm_read_uint24((const uint8_t *)"\x01\x02\x03");
    assert_int_equal(value, 0x030201);

    libspdm_write_uint24(buffer, 0x030201);
    assert_memory_equal(buffer, "\x01\x02\x03", sizeof(buffer));

    libspdm_write_uint24(buffer, 0x00FFFFFF);
    assert_int_equal(libspdm_read_uint24(buffer), 0x00FFFFFF);

    libspdm_write_uint24(buffer, 0x00000000);
    assert_int_equal(libspdm_read_uint24(buffer), 0x00000000);
}

/**
 * Test 4: Test libspdm_read_uint32 and libspdm_write_uint32.
 **/
static void libspdm_test_common_read_write_uint32(void **state)
{
    uint8_t buffer[4];
    uint32_t value;

    value = libspdm_read_uint32((const uint8_t *)"\x01\x02\x03\x04");
    assert_int_equal(value, 0x04030201);

    libspdm_write_uint32(buffer, 0x04030201);
    assert_memory_equal(buffer, "\x01\x02\x03\x04", sizeof(buffer));

    libspdm_write_uint32(buffer, 0xFFFFFFFF);
    assert_int_equal(libspdm_read_uint32(buffer), 0xFFFFFFFF);

    libspdm_write_uint32(buffer, 0x00000000);
    assert_int_equal(libspdm_read_uint32(buffer), 0x00000000);
}

/**
 * Test 5: Test libspdm_read_uint64 and libspdm_write_uint64.
 **/
static void libspdm_test_common_read_write_uint64(void **state)
{
    uint8_t buffer[8];
    uint64_t value;

    value = libspdm_read_uint64((const uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08");
    assert_int_equal(value, UINT64_C(0x0807060504030201));

    libspdm_write_uint64(buffer, UINT64_C(0x0807060504030201));
    assert_memory_equal(buffer, "\x01\x02\x03\x04\x05\x06\x07\x08", sizeof(buffer));

    libspdm_write_uint64(buffer, UINT64_C(0xFFFFFFFFFFFFFFFF));
    assert_int_equal(libspdm_read_uint64(buffer), UINT64_C(0xFFFFFFFFFFFFFFFF));

    libspdm_write_uint64(buffer, UINT64_C(0x0000000000000000));
    assert_int_equal(libspdm_read_uint64(buffer), UINT64_C(0x0000000000000000));
}

int libspdm_common_support_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_common_context_data_case1),
        cmocka_unit_test(libspdm_test_common_read_write_uint16),
        cmocka_unit_test(libspdm_test_common_read_write_uint24),
        cmocka_unit_test(libspdm_test_common_read_write_uint32),
        cmocka_unit_test(libspdm_test_common_read_write_uint64),

    };

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
