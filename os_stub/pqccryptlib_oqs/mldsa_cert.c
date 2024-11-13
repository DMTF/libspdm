/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_pqccrypt_lib.h"

#if LIBSPDM_ML_DSA_SUPPORT
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
