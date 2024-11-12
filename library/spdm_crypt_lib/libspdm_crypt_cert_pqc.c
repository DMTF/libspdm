/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"

#if LIBSPDM_CERT_PARSE_SUPPORT

/**
 * Certificate Check for SPDM leaf cert.
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 * @param[in]  pqc_asym_algo        SPDM pqc_asym_algo
 * @param[in]  base_hash_algo        SPDM base_hash_algo
 * @param[in]  is_requester          Is the function verifying a cert as a requester or responder.
 * @param[in]  cert_model            One of the SPDM_CERTIFICATE_INFO_CERT_MODEL_* macros.
 *
 * @retval  true   Success.
 * @retval  false  Certificate is not valid.
 **/
bool libspdm_x509_pqc_certificate_check(const uint8_t *cert, size_t cert_size,
                                        uint32_t pqc_asym_algo, uint32_t base_hash_algo,
                                        bool is_requester, uint8_t cert_model)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return true;
}

/**
 * Certificate Check for SPDM leaf cert when set_cert.
 *
 * @param[in]  cert                  Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size             The size of certificate data in bytes.
 * @param[in]  pqc_asym_algo         SPDM pqc_asym_algo
 * @param[in]  base_hash_algo        SPDM base_hash_algo
 * @param[in]  is_requester          Is the function verifying a cert as a requester or responder.
 * @param[in]  cert_model            One of the SPDM_CERTIFICATE_INFO_CERT_MODEL_* macros.
 *
 * @retval  true   Success.
 * @retval  false  Certificate is not valid.
 **/
bool libspdm_x509_pqc_set_cert_certificate_check(const uint8_t *cert, size_t cert_size,
                                                 uint32_t pqc_asym_algo, uint32_t base_hash_algo,
                                                 bool is_requester, uint8_t cert_model)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return true;
}

/**
 * This function verifies the integrity of certificate chain data without spdm_cert_chain_t header.
 *
 * @param  cert_chain_data       The certificate chain data without spdm_cert_chain_t header.
 * @param  cert_chain_data_size  Size in bytes of the certificate chain data.
 * @param  pqc_asym_algo         SPDM pqc_asym_algo
 * @param  base_hash_algo        SPDM base_hash_algo
 * @param  is_requester_cert     Is the function verifying requester or responder cert.
 * @param  cert_model            One of the SPDM_CERTIFICATE_INFO_CERT_MODEL_* macros.
 *
 * @retval true  Certificate chain data integrity verification pass.
 * @retval false Certificate chain data integrity verification fail.
 **/
bool libspdm_verify_pqc_cert_chain_data(uint8_t *cert_chain_data, size_t cert_chain_data_size,
                                        uint32_t pqc_asym_algo, uint32_t base_hash_algo,
                                        bool is_requester_cert, uint8_t cert_model)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return true;
}

/**
 * This function verifies the integrity of certificate chain buffer including
 * spdm_cert_chain_t header.
 *
 * @param  base_hash_algo          SPDM base_hash_algo
 * @param  pqc_asym_algo           SPDM pqc_asym_algo
 * @param  cert_chain_buffer       The certificate chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size  Size in bytes of the certificate chain buffer.
 * @param  is_requester_cert       Is the function verifying requester or responder cert.
 * @param  cert_model              One of the SPDM_CERTIFICATE_INFO_CERT_MODEL_* macros.
 *
 * @retval true   Certificate chain buffer integrity verification pass.
 * @retval false  Certificate chain buffer integrity verification fail.
 **/
bool libspdm_verify_pqc_certificate_chain_buffer(uint32_t base_hash_algo, uint32_t pqc_asym_algo,
                                                 const void *cert_chain_buffer,
                                                 size_t cert_chain_buffer_size,
                                                 bool is_requester_cert, uint8_t cert_model)
{
    // TBD 1.4 - Need cert chain parsing for PQC.
    return true;
}

/**
 * Retrieve the asymmetric public key from one DER-encoded X509 certificate,
 * based upon negotiated asymmetric or requester asymmetric algorithm.
 *
 * @param  base_hash_algo        SPDM base_hash_algo.
 * @param  pqc_asym_alg          SPDM pqc_asym_algo or req_pqc_asym_alg.
 * @param  cert_chain_data       Certificate chain data with spdm_cert_chain_t header.
 * @param  cert_chain_data_size  Size in bytes of the certificate chain data.
 * @param  public_key            Pointer to newly generated asymmetric context which contain the
 *                               retrieved public key component.
 *
 * @retval  true   Public key was retrieved successfully.
 * @retval  false  Fail to retrieve public key from X509 certificate.
 **/
bool libspdm_get_pqc_leaf_cert_public_key_from_cert_chain(uint32_t base_hash_algo,
                                                          uint32_t pqc_asym_alg,
                                                          uint8_t *cert_chain_data,
                                                          size_t cert_chain_data_size,
                                                          void **public_key)
{
    size_t hash_size;
    const uint8_t *cert_buffer;
    size_t cert_buffer_size;
    bool result;

    hash_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_data = cert_chain_data + sizeof(spdm_cert_chain_t) + hash_size;
    cert_chain_data_size = cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_size);

    /* Get leaf cert from cert chain */
    result = libspdm_x509_get_cert_from_cert_chain(cert_chain_data,
                                                   cert_chain_data_size, -1,
                                                   &cert_buffer, &cert_buffer_size);
    if (!result) {
        return false;
    }

    result = libspdm_pqc_asym_get_public_key_from_x509(
        pqc_asym_alg,
        cert_buffer, cert_buffer_size, public_key);
    if (!result) {
        return false;
    }

    return true;
}

#endif
