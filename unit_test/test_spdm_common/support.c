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

/**
 * Test 6: Test libspdm_module_version.
 * Expected Behavior: byte 3 holds the major version, byte 2 the minor version, byte 1 the patch
 * version and byte 0 the alpha value.
 **/
static void libspdm_test_common_module_version(void **state)
{
    uint32_t version;

    version = libspdm_module_version();

    assert_int_equal((version >> 24) & 0xFF, LIBSPDM_MAJOR_VERSION);
    assert_int_equal((version >> 16) & 0xFF, LIBSPDM_MINOR_VERSION);
    assert_int_equal((version >> 8) & 0xFF, LIBSPDM_PATCH_VERSION);
    assert_int_equal(version & 0xFF, LIBSPDM_ALPHA);
}

/**
 * Test 7: Test libspdm_get_fips_mode.
 * Expected Behavior: it returns whether libspdm was built with LIBSPDM_FIPS_MODE.
 **/
static void libspdm_test_common_get_fips_mode(void **state)
{
    assert_int_equal(libspdm_get_fips_mode(), LIBSPDM_FIPS_MODE);
}

/* SPDM 1.2 added the SM2, SM3, SM4 and EdDSA algorithms, so the algorithm masks differ between
 * these two groups of versions. */
static const uint8_t m_libspdm_versions_10_11[] = {
    SPDM_MESSAGE_VERSION_10, SPDM_MESSAGE_VERSION_11
};

static const uint8_t m_libspdm_versions_12_14[] = {
    SPDM_MESSAGE_VERSION_12, SPDM_MESSAGE_VERSION_13, SPDM_MESSAGE_VERSION_14
};

static void set_connection_version(libspdm_context_t *spdm_context, uint8_t version)
{
    spdm_context->connection_info.version = version << SPDM_VERSION_NUMBER_SHIFT_BIT;
}

/**
 * Test 8: Test libspdm_mask_base_hash_algo for SPDM 1.0 and 1.1.
 * Expected Behavior: only the BaseHashAlgo bits that SPDM 1.0 defines remain set.
 **/
static void libspdm_test_common_mask_base_hash_algo_10(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_10_11); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_10_11[index]);

        assert_int_equal(libspdm_mask_base_hash_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512);
    }
}

/**
 * Test 9: Test libspdm_mask_base_hash_algo for SPDM 1.2 through 1.4.
 * Expected Behavior: only the BaseHashAlgo bits that SPDM 1.2 defines, which add TPM_ALG_SM3_256,
 * remain set.
 **/
static void libspdm_test_common_mask_base_hash_algo_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_base_hash_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
                         SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256);
    }
}

/**
 * Test 10: Test libspdm_mask_measurement_hash_algo for SPDM 1.0 and 1.1.
 * Expected Behavior: only the MeasurementHashAlgo bits that SPDM 1.0 defines remain set.
 **/
static void libspdm_test_common_mask_measurement_hash_algo_10(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_10_11); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_10_11[index]);

        assert_int_equal(libspdm_mask_measurement_hash_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512);
    }
}

/**
 * Test 11: Test libspdm_mask_measurement_hash_algo for SPDM 1.2 through 1.4.
 * Expected Behavior: only the MeasurementHashAlgo bits that SPDM 1.2 defines, which add
 * TPM_ALG_SM3_256, remain set.
 **/
static void libspdm_test_common_mask_measurement_hash_algo_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_measurement_hash_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512 |
                         SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256);
    }
}

/**
 * Test 12: Test libspdm_mask_measurement_specification.
 * Expected Behavior: only the DMTF bit of MeasurementSpecification remains set.
 **/
static void libspdm_test_common_mask_measurement_specification(void **state)
{
    assert_int_equal(libspdm_mask_measurement_specification(0xFF),
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);
}

/**
 * Test 13: Test libspdm_mask_mel_specification for SPDM 1.3 and 1.4.
 * Expected Behavior: only the DMTF bit of MELspecification remains set.
 **/
static void libspdm_test_common_mask_mel_specification(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(libspdm_mask_mel_specification(spdm_context, 0xFF),
                     SPDM_MEL_SPECIFICATION_DMTF);

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_14);
    assert_int_equal(libspdm_mask_mel_specification(spdm_context, 0xFF),
                     SPDM_MEL_SPECIFICATION_DMTF);
}

/**
 * Test 14: Test libspdm_mask_base_asym_algo for SPDM 1.0 and 1.1.
 * Expected Behavior: only the BaseAsymAlgo bits that SPDM 1.0 defines remain set.
 **/
static void libspdm_test_common_mask_base_asym_algo_10(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_10_11); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_10_11[index]);

        assert_int_equal(libspdm_mask_base_asym_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
    }
}

/**
 * Test 15: Test libspdm_mask_base_asym_algo for SPDM 1.2 through 1.4.
 * Expected Behavior: only the BaseAsymAlgo bits that SPDM 1.2 defines, which add
 * TPM_ALG_SM2_ECC_SM2_P256, EdDSA ed25519 and EdDSA ed448, remain set.
 **/
static void libspdm_test_common_mask_base_asym_algo_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_base_asym_algo(spdm_context, 0xFFFFFFFF),
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
    }
}

/**
 * Test 16: Test libspdm_mask_alg_supported for DHE and SPDM 1.1.
 * Expected Behavior: only the DHE AlgSupported bits that SPDM 1.1 defines remain set.
 **/
static void libspdm_test_common_mask_alg_supported_dhe_11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_11);

    assert_int_equal(libspdm_mask_alg_supported(
                         spdm_context, SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE, 0xFFFF),
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                     SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1);
}

/**
 * Test 17: Test libspdm_mask_alg_supported for DHE and SPDM 1.2 through 1.4.
 * Expected Behavior: only the DHE AlgSupported bits that SPDM 1.2 defines, which add SM2_P256,
 * remain set.
 **/
static void libspdm_test_common_mask_alg_supported_dhe_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_alg_supported(
                             spdm_context, SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
                             0xFFFF),
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
                         SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256);
    }
}

/**
 * Test 18: Test libspdm_mask_alg_supported for AEAD and SPDM 1.1.
 * Expected Behavior: only the AEAD AlgSupported bits that SPDM 1.1 defines remain set.
 **/
static void libspdm_test_common_mask_alg_supported_aead_11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_11);

    assert_int_equal(libspdm_mask_alg_supported(
                         spdm_context, SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
                         0xFFFF),
                     SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                     SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                     SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305);
}

/**
 * Test 19: Test libspdm_mask_alg_supported for AEAD and SPDM 1.2 through 1.4.
 * Expected Behavior: only the AEAD AlgSupported bits that SPDM 1.2 defines, which add AEAD_SM4_GCM,
 * remain set.
 **/
static void libspdm_test_common_mask_alg_supported_aead_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_alg_supported(
                             spdm_context, SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
                             0xFFFF),
                         SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                         SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                         SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 |
                         SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM);
    }
}

/**
 * Test 20: Test libspdm_mask_alg_supported for ReqBaseAsymAlg and SPDM 1.1.
 * Expected Behavior: only the ReqBaseAsymAlg AlgSupported bits that SPDM 1.1 defines, which are
 * those of BaseAsymAlgo, remain set.
 **/
static void libspdm_test_common_mask_alg_supported_req_base_asym_alg_11(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_11);

    assert_int_equal(libspdm_mask_alg_supported(
                         spdm_context,
                         SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
                         0xFFFF),
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                     SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
}

/**
 * Test 21: Test libspdm_mask_alg_supported for ReqBaseAsymAlg and SPDM 1.2 through 1.4.
 * Expected Behavior: only the ReqBaseAsymAlg AlgSupported bits that SPDM 1.2 defines, which are
 * those of BaseAsymAlgo, remain set.
 **/
static void libspdm_test_common_mask_alg_supported_req_base_asym_alg_12(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_alg_supported(
                             spdm_context,
                             SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
                             0xFFFF),
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                         SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448);
    }
}

/**
 * Test 22: Test libspdm_mask_alg_supported for KeySchedule and SPDM 1.1 through 1.4.
 * Expected Behavior: only the SPDM key schedule bit of KeySchedule AlgSupported remains set.
 **/
static void libspdm_test_common_mask_alg_supported_key_schedule(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    set_connection_version(spdm_context, SPDM_MESSAGE_VERSION_11);
    assert_int_equal(libspdm_mask_alg_supported(
                         spdm_context, SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
                         0xFFFF),
                     SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_libspdm_versions_12_14); index++) {
        set_connection_version(spdm_context, m_libspdm_versions_12_14[index]);

        assert_int_equal(libspdm_mask_alg_supported(
                             spdm_context,
                             SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
                             0xFFFF),
                         SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM);
    }
}

static libspdm_test_context_t m_libspdm_common_support_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    NULL,
    NULL,
};

int libspdm_common_support_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_common_context_data_case1),
        cmocka_unit_test(libspdm_test_common_read_write_uint16),
        cmocka_unit_test(libspdm_test_common_read_write_uint24),
        cmocka_unit_test(libspdm_test_common_read_write_uint32),
        cmocka_unit_test(libspdm_test_common_read_write_uint64),
        cmocka_unit_test(libspdm_test_common_module_version),
        cmocka_unit_test(libspdm_test_common_get_fips_mode),
        cmocka_unit_test(libspdm_test_common_mask_base_hash_algo_10),
        cmocka_unit_test(libspdm_test_common_mask_base_hash_algo_12),
        cmocka_unit_test(libspdm_test_common_mask_measurement_hash_algo_10),
        cmocka_unit_test(libspdm_test_common_mask_measurement_hash_algo_12),
        cmocka_unit_test(libspdm_test_common_mask_measurement_specification),
        cmocka_unit_test(libspdm_test_common_mask_mel_specification),
        cmocka_unit_test(libspdm_test_common_mask_base_asym_algo_10),
        cmocka_unit_test(libspdm_test_common_mask_base_asym_algo_12),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_dhe_11),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_dhe_12),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_aead_11),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_aead_12),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_req_base_asym_alg_11),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_req_base_asym_alg_12),
        cmocka_unit_test(libspdm_test_common_mask_alg_supported_key_schedule),

    };

    libspdm_setup_test_context(&m_libspdm_common_support_test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
