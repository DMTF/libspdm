/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 Certificate Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <crypto/evp.h>

#if LIBSPDM_ML_DSA_SUPPORT

extern uint8_t m_mldsa44_oid[];
extern uint8_t m_mldsa44_oid_size;

extern uint8_t m_mldsa65_oid[];
extern uint8_t m_mldsa65_oid_size;

extern uint8_t m_mldsa87_oid[];
extern uint8_t m_mldsa87_oid_size;

/**
 * Retrieve the mldsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated mldsa context which contain the retrieved
 *                          mldsa public key component. Use mldsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   mldsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve mldsa public key from X509 certificate.
 *
 **/
bool libspdm_mldsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                            void **dsa_context)
{
    size_t nid;
    const uint8_t *key_data;
    size_t key_size;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;
    bool ret;

    ptr = (uint8_t*)(size_t)cert;
    obj_len = 0;
    end = ptr + cert_size;

    /* Certificate SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Data SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Version Count[] */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Serial Number INTEGER */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Signature Algorithm SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Issuer SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Validity SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Subject SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Subject Public Key Info SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Public Key Algorithm SEQUENCE */
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
    if ((obj_len == m_mldsa44_oid_size) &&
        libspdm_consttime_is_mem_equal (ptr, m_mldsa44_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_44;
        key_size = 1312;
    } else if ((obj_len == m_mldsa65_oid_size) &&
               libspdm_consttime_is_mem_equal (ptr, m_mldsa65_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_65;
        key_size = 1952;
    } else if ((obj_len == m_mldsa87_oid_size) &&
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

extern uint8_t m_slhdsa_sha2_128s_oid[];
extern uint8_t m_slhdsa_sha2_128s_oid_size;

extern uint8_t m_slhdsa_shake_128s_oid[];
extern uint8_t m_slhdsa_shake_128s_oid_size;

extern uint8_t m_slhdsa_sha2_128f_oid[];
extern uint8_t m_slhdsa_sha2_128f_oid_size;

extern uint8_t m_slhdsa_shake_128f_oid[];
extern uint8_t m_slhdsa_shake_128f_oid_size;

extern uint8_t m_slhdsa_sha2_192s_oid[];
extern uint8_t m_slhdsa_sha2_192s_oid_size;

extern uint8_t m_slhdsa_shake_192s_oid[];
extern uint8_t m_slhdsa_shake_192s_oid_size;

extern uint8_t m_slhdsa_sha2_192f_oid[];
extern uint8_t m_slhdsa_sha2_192f_oid_size;

extern uint8_t m_slhdsa_shake_192f_oid[];
extern uint8_t m_slhdsa_shake_192f_oid_size;

extern uint8_t m_slhdsa_sha2_256s_oid[];
extern uint8_t m_slhdsa_sha2_256s_oid_size;

extern uint8_t m_slhdsa_shake_256s_oid[];
extern uint8_t m_slhdsa_shake_256s_oid_size;

extern uint8_t m_slhdsa_sha2_256f_oid[];
extern uint8_t m_slhdsa_sha2_256f_oid_size;

extern uint8_t m_slhdsa_shake_256f_oid[];
extern uint8_t m_slhdsa_shake_256f_oid_size;

/**
 * Retrieve the slhdsa public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size    Size of the X509 certificate in bytes.
 * @param[out] dsa_context  Pointer to newly generated slhdsa context which contain the retrieved
 *                          slhdsa public key component. Use slhdsa_free() function to free the
 *                          resource.
 *
 * If cert is NULL, then return false.
 * If dsa_context is NULL, then return false.
 *
 * @retval  true   slhdsa public key was retrieved successfully.
 * @retval  false  Fail to retrieve slhdsa public key from X509 certificate.
 *
 **/
bool libspdm_slhdsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                             void **dsa_context)
{
    size_t nid;
    const uint8_t *key_data;
    size_t key_size;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;
    bool ret;

    ptr = (uint8_t*)(size_t)cert;
    obj_len = 0;
    end = ptr + cert_size;

    /* Certificate SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Data SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Version Count[] */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Serial Number INTEGER */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Signature Algorithm SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Issuer SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Validity SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Subject SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

    /* Subject Public Key Info SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* Public Key Algorithm SEQUENCE */
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
