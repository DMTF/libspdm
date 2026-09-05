/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"

static bool m_expected_is_requester_cert;

bool libspdm_tpm_device_init(void)
{
    return true;
}

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    uint8_t *data;

    data = malloc(1);
    assert_non_null(data);
    data[0] = 0;
    *buffer = data;
    *size = 1;
    return true;
}

uint32_t libspdm_get_hash_size(uint32_t base_hash_algo)
{
    return 32;
}

bool libspdm_verify_cert_chain_data(
    uint8_t spdm_version,
    uint8_t *cert_chain_data, size_t cert_chain_data_size,
    uint32_t base_asym_algo, uint32_t pqc_asym_algo, uint32_t base_hash_algo,
    bool is_requester_cert, uint8_t cert_model)
{
    assert_int_equal(is_requester_cert, m_expected_is_requester_cert);
    return true;
}

bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                           size_t cert_chain_length,
                                           const int32_t cert_index,
                                           const uint8_t **cert,
                                           size_t *cert_length)
{
    if (cert != NULL) {
        *cert = cert_chain;
    }
    if (cert_length != NULL) {
        *cert_length = cert_chain_length;
    }
    return true;
}

bool libspdm_hash_all(uint32_t base_hash_algo, const void *data,
                      size_t data_size, uint8_t *hash_value)
{
    libspdm_zero_mem(hash_value, libspdm_get_hash_size(base_hash_algo));
    return true;
}

static void libspdm_test_tpm_classical_cert_chain_role(void **state)
{
    bool status;
    void *data;
    size_t size;

    m_expected_is_requester_cert = true;
    status = libspdm_read_requester_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, NULL, NULL);
    assert_true(status);
    free(data);

    m_expected_is_requester_cert = false;
    status = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, NULL, NULL);
    assert_true(status);
    free(data);
}

static void libspdm_test_tpm_pqc_cert_chain_role(void **state)
{
    bool status;
    void *data;
    size_t size;

    m_expected_is_requester_cert = true;
    status = libspdm_read_pqc_requester_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44,
        &data, &size, NULL, NULL);
    assert_true(status);
    free(data);

    m_expected_is_requester_cert = false;
    status = libspdm_read_pqc_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44,
        &data, &size, NULL, NULL);
    assert_true(status);
    free(data);
}

int main(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(libspdm_test_tpm_classical_cert_chain_role),
        cmocka_unit_test(libspdm_test_tpm_pqc_cert_chain_role),
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}
