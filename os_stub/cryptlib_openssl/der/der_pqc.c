/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

#if LIBSPDM_ML_DSA_SUPPORT

/* OID definition */

uint8_t m_mldsa44_oid[] = {
    /* 2.16.840.1.101.3.4.3.17 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
};
uint8_t m_mldsa44_oid_size = sizeof(m_mldsa44_oid);

uint8_t m_mldsa65_oid[] = {
    /* 2.16.840.1.101.3.4.3.18 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
};
uint8_t m_mldsa65_oid_size = sizeof(m_mldsa65_oid);

uint8_t m_mldsa87_oid[] = {
    /* 2.16.840.1.101.3.4.3.19 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
};
uint8_t m_mldsa87_oid_size = sizeof(m_mldsa87_oid);

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_mldsa_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
bool libspdm_mldsa_get_public_key_from_der(const uint8_t *der_data,
                                           size_t der_size,
                                           void **dsa_context)
{
    size_t nid;
    const uint8_t *key_data;
    size_t key_size;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;
    bool ret;

    ptr = (uint8_t*)(size_t)der_data;
    obj_len = 0;
    end = ptr + der_size;

    /* SubjectPublicKeyInfo SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* AlgorithmIdentifier SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* OID */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
    if (!ret) {
        return false;
    }
    if ((obj_len == sizeof(m_mldsa44_oid)) &&
        libspdm_consttime_is_mem_equal (ptr, m_mldsa44_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_44;
        key_size = 1312;
    } else if ((obj_len == sizeof(m_mldsa65_oid)) &&
               libspdm_consttime_is_mem_equal (ptr, m_mldsa65_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_65;
        key_size = 1952;
    } else if ((obj_len == sizeof(m_mldsa87_oid)) &&
               libspdm_consttime_is_mem_equal (ptr, m_mldsa87_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_87;
        key_size = 2592;
    } else {
        return false;
    }
    ptr += obj_len;

    /* PubKey */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_BIT_STRING);
    if (!ret) {
        return false;
    }
    if (obj_len == key_size) {
        key_data = ptr;
    } else if ((obj_len == key_size + 1) && (ptr[0] == 0)) {
        key_data = ptr + 1;
    } else {
        return false;
    }

    *dsa_context = libspdm_mldsa_new (nid);
    ret = libspdm_mldsa_set_pubkey (*dsa_context, key_data, key_size);
    if (!ret) {
        return false;
    }
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

/* OID definition */

uint8_t m_slhdsa_sha2_128s_oid[] = {
    /* 2.16.840.1.101.3.4.3.20 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
};
uint8_t m_slhdsa_sha2_128s_oid_size = sizeof(m_slhdsa_sha2_128s_oid);

uint8_t m_slhdsa_sha2_128f_oid[] = {
    /* 2.16.840.1.101.3.4.3.21 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15,
};
uint8_t m_slhdsa_sha2_128f_oid_size = sizeof(m_slhdsa_sha2_128f_oid);

uint8_t m_slhdsa_sha2_192s_oid[] = {
    /* 2.16.840.1.101.3.4.3.22 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16,
};
uint8_t m_slhdsa_sha2_192s_oid_size = sizeof(m_slhdsa_sha2_192s_oid);

uint8_t m_slhdsa_sha2_192f_oid[] = {
    /* 2.16.840.1.101.3.4.3.23 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17,
};
uint8_t m_slhdsa_sha2_192f_oid_size = sizeof(m_slhdsa_sha2_192f_oid);

uint8_t m_slhdsa_sha2_256s_oid[] = {
    /* 2.16.840.1.101.3.4.3.24 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18,
};
uint8_t m_slhdsa_sha2_256s_oid_size = sizeof(m_slhdsa_sha2_256s_oid);

uint8_t m_slhdsa_sha2_256f_oid[] = {
    /* 2.16.840.1.101.3.4.3.25 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19,
};
uint8_t m_slhdsa_sha2_256f_oid_size = sizeof(m_slhdsa_sha2_256f_oid);

uint8_t m_slhdsa_shake_128s_oid[] = {
    /* 2.16.840.1.101.3.4.3.26 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1a,
};
uint8_t m_slhdsa_shake_128s_oid_size = sizeof(m_slhdsa_shake_128s_oid);

uint8_t m_slhdsa_shake_128f_oid[] = {
    /* 2.16.840.1.101.3.4.3.27 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1b,
};
uint8_t m_slhdsa_shake_128f_oid_size = sizeof(m_slhdsa_shake_128f_oid);

uint8_t m_slhdsa_shake_192s_oid[] = {
    /* 2.16.840.1.101.3.4.3.28 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1c,
};
uint8_t m_slhdsa_shake_192s_oid_size = sizeof(m_slhdsa_shake_192s_oid);

uint8_t m_slhdsa_shake_192f_oid[] = {
    /* 2.16.840.1.101.3.4.3.29 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1d,
};
uint8_t m_slhdsa_shake_192f_oid_size = sizeof(m_slhdsa_shake_192f_oid);

uint8_t m_slhdsa_shake_256s_oid[] = {
    /* 2.16.840.1.101.3.4.3.30 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1e,
};
uint8_t m_slhdsa_shake_256s_oid_size = sizeof(m_slhdsa_shake_256s_oid);

uint8_t m_slhdsa_shake_256f_oid[] = {
    /* 2.16.840.1.101.3.4.3.21 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1f,
};
uint8_t m_slhdsa_shake_256f_oid_size = sizeof(m_slhdsa_shake_256f_oid);

/**
 * Generates DSA context from DER-encoded public key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * OID is defined in https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates
 *
 * @param[in]  der_data     Pointer to the DER-encoded public key data.
 * @param[in]  der_size     Size of the DER-encoded public key data in bytes.
 * @param[out] dsa_context  Pointer to newly generated DSA context which contains the
 *                          DSA public key component.
 *                          Use libspdm_slhdsa_free() function to free the resource.
 *
 * If der_data is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   DSA context was generated successfully.
 * @retval  false  Invalid DER public key data.
 *
 **/
bool libspdm_slhdsa_get_public_key_from_der(const uint8_t *der_data,
                                            size_t der_size,
                                            void **dsa_context)
{
    size_t nid;
    const uint8_t *key_data;
    size_t key_size;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;
    bool ret;

    ptr = (uint8_t*)(size_t)der_data;
    obj_len = 0;
    end = ptr + der_size;

    /* SubjectPublicKeyInfo SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* AlgorithmIdentifier SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* OID */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
    if (!ret) {
        return false;
    }
    if ((obj_len == m_slhdsa_sha2_128s_oid_size) &&
        libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_128s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S;
        key_size = 32;
    } else if ((obj_len == m_slhdsa_shake_128s_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_128s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S;
        key_size = 32;
    } else if ((obj_len == m_slhdsa_sha2_128f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_128f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F;
        key_size = 32;
    } else if ((obj_len == m_slhdsa_shake_128f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_128f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F;
        key_size = 32;
    } else if ((obj_len == m_slhdsa_sha2_192s_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_192s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S;
        key_size = 48;
    } else if ((obj_len == m_slhdsa_shake_192s_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_192s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S;
        key_size = 48;
    } else if ((obj_len == m_slhdsa_sha2_192f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_192f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F;
        key_size = 48;
    } else if ((obj_len == m_slhdsa_shake_192f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_192f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F;
        key_size = 48;
    } else if ((obj_len == m_slhdsa_sha2_256s_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_256s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S;
        key_size = 64;
    } else if ((obj_len == m_slhdsa_shake_256s_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_256s_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S;
        key_size = 64;
    } else if ((obj_len == m_slhdsa_sha2_256f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_sha2_256f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F;
        key_size = 64;
    } else if ((obj_len == m_slhdsa_shake_256f_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_slhdsa_shake_256f_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F;
        key_size = 64;
    } else {
        return false;
    }
    ptr += obj_len;

    /* PubKey */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_BIT_STRING);
    if (!ret) {
        return false;
    }
    if (obj_len == key_size) {
        key_data = ptr;
    } else if ((obj_len == key_size + 1) && (ptr[0] == 0)) {
        key_data = ptr + 1;
    } else {
        return false;
    }

    *dsa_context = libspdm_slhdsa_new (nid);
    ret = libspdm_slhdsa_set_pubkey (*dsa_context, key_data, key_size);
    if (!ret) {
        return false;
    }
    return true;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
