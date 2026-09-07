/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "keys.h"

extern size_t libspdm_fill_measurement_image_hash_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block);

static bool is_tpm_available(void)
{
    return (getenv("TPM2TOOLS_TCTI") != NULL);
}

/* --------------------------------------------------------------------------
 * Offline / Parameter Validation & Invariant Tests
 * -------------------------------------------------------------------------- */

static void test_tpm_device_init(void **state)
{
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_device_init();
    assert_true(status);

    /* Test idempotency */
    status = libspdm_tpm_device_init();
    assert_true(status);
}

static void test_tpm_key_handle_null_params(void **state)
{
    void *context = NULL;
    bool status;

    status = libspdm_tpm_get_pvt_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pvt_key_handle("handle:0x81000021", NULL);
    assert_false(status);

    status = libspdm_tpm_get_pub_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pub_key_handle("handle:0x81000021", NULL);
    assert_false(status);
}

static void test_tpm_read_pcr_validation(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    size = sizeof(buffer);

    /* NULL buffer */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, NULL, &size);
    assert_false(status);

    /* NULL size */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, NULL);
    assert_false(status);

    /* Unsupported algorithm */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(0xFFFFFFFF, 0, buffer, &size);
    assert_false(status);

    /* Invalid index (>= 24) */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 24, buffer, &size);
    assert_false(status);

    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 100, buffer, &size);
    assert_false(status);

    /* Buffer undersize check: should return required size (32 for SHA256) */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 32);

    /* Buffer undersize check: SHA384 requires 48 bytes */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 48);
}

static void test_tpm_read_nv_validation(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    status = libspdm_tpm_read_nv(0x1500021, NULL, &size);
    assert_false(status);

    status = libspdm_tpm_read_nv(0x1500021, &buffer, NULL);
    assert_false(status);
    assert_null(buffer);
}

static void test_spdm_tpm_security_stubs(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *context = NULL;
    bool status;

    /* Raw private keys must never be readable from the TPM stub */
    status = libspdm_read_responder_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_responder_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
    status = libspdm_read_requester_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_requester_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);
#endif

    status = libspdm_read_responder_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_read_requester_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);
}

static void test_spdm_tpm_meas_validation(void **state)
{
    spdm_measurement_block_dmtf_t block;
    size_t block_size;

    /* use_bit_stream is not supported for TPM */
    block_size = libspdm_fill_measurement_image_hash_block(
        true, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, &block);
    assert_int_equal(block_size, 0);

    /* measurements_index 0 is invalid */
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, &block);
    assert_int_equal(block_size, 0);
}

static void test_spdm_tpm_cert_slot_validation(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    bool status;

    /* Unsupported slot (slot 7 is not in default 0;1;4 mask) */
    status = libspdm_read_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    status = libspdm_read_responder_public_certificate_chain_per_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Out of range slot (>= SPDM_MAX_SLOT_COUNT) */
    status = libspdm_read_responder_root_public_certificate_slot(
        8, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Algorithm 0 is invalid */
    status = libspdm_read_responder_certificate(0, &data, &size);
    assert_false(status);

    /* PQC responder root certificate slot test with invalid slot */
    status = libspdm_read_pqc_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);
}

/* --------------------------------------------------------------------------
 * Live TPM Simulator Tests (gated by TPM2TOOLS_TCTI)
 * -------------------------------------------------------------------------- */

static void test_tpm_live_read_pcr(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);

    /* Read PCR 1 */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);
}

static void test_tpm_live_read_nv(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_read_nv(
        LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0, &buffer, &size);
    assert_true(status);
    assert_non_null(buffer);
    assert_true(size > 0);

    free(buffer);
}

static void test_spdm_tpm_live_read_certchain(void **state)
{
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    spdm_cert_chain_t *chain_header;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > sizeof(spdm_cert_chain_t));
    assert_non_null(hash);
    assert_int_equal(hash_size, 32);

    chain_header = (spdm_cert_chain_t *)cert_chain;
    assert_int_equal(chain_header->length, (uint32_t)cert_chain_size);

    free(cert_chain);

    /* Test root public certificate extraction */
    status = libspdm_read_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test leaf certificate extraction */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test PQC wrapper calls responder cert */
    status = libspdm_read_pqc_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    free(cert_chain);
}

static void test_spdm_tpm_live_fill_meas_block(void **state)
{
    uint8_t buffer[512];
    spdm_measurement_block_dmtf_t *block;
    size_t block_size;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    block = (spdm_measurement_block_dmtf_t *)buffer;
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, block);

    assert_true(block_size > 0);
    assert_int_equal(block->measurement_block_common_header.index, 1);
    assert_int_equal(block->measurement_block_common_header.measurement_specification,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    assert_int_equal(block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size, 32);
    assert_int_equal(block_size, sizeof(spdm_measurement_block_dmtf_t) + 32);
}

static void test_spdm_tpm_live_sign_and_verify(void **state)
{
    uint8_t digest[32];
    uint8_t signature[128];
    size_t sig_size = sizeof(signature);
    void *cert_data = NULL;
    size_t cert_size = 0;
    void *context = NULL;
    bool status;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    /* Prepare a test digest */
    for (i = 0; i < sizeof(digest); i++) {
        digest[i] = (uint8_t)(i + 1);
    }

    /* Perform TPM signature */
    status = libspdm_responder_data_sign(
        NULL, SPDM_MESSAGE_VERSION_12, 0, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
        digest, sizeof(digest), signature, &sig_size);
    assert_true(status);
    assert_true(sig_size > 0);

    /* Read the leaf certificate from NV to verify the signature */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_data, &cert_size);
    assert_true(status);
    assert_non_null(cert_data);

    /* Extract public key and verify signature */
    status = libspdm_asym_get_public_key_from_x509(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        cert_data, cert_size, &context);
    assert_true(status);
    assert_non_null(context);

    status = libspdm_asym_verify_hash(
        SPDM_MESSAGE_VERSION_12, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        context, digest, sizeof(digest), signature, sig_size);
    assert_true(status);

    libspdm_asym_free(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, context);
    free(cert_data);
}

/* --------------------------------------------------------------------------
 * Main Test Runner
 * -------------------------------------------------------------------------- */

static int libspdm_spdm_tpm_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Offline tests */
        cmocka_unit_test(test_tpm_device_init),
        cmocka_unit_test(test_tpm_key_handle_null_params),
        cmocka_unit_test(test_tpm_read_pcr_validation),
        cmocka_unit_test(test_tpm_read_nv_validation),
        cmocka_unit_test(test_spdm_tpm_security_stubs),
        cmocka_unit_test(test_spdm_tpm_meas_validation),
        cmocka_unit_test(test_spdm_tpm_cert_slot_validation),

        /* Live TPM tests */
        cmocka_unit_test(test_tpm_live_read_pcr),
        cmocka_unit_test(test_tpm_live_read_nv),
        cmocka_unit_test(test_spdm_tpm_live_read_certchain),
        cmocka_unit_test(test_spdm_tpm_live_fill_meas_block),
        cmocka_unit_test(test_spdm_tpm_live_sign_and_verify),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}

int main(void)
{
    return libspdm_spdm_tpm_test_main();
}
