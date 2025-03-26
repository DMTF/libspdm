/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal_pqccrypt_lib.h"

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Allocates and initializes one DSA context for subsequent use.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the DSA context that has been initialized.
 **/
void *libspdm_mldsa_new(size_t nid)
{
    OQS_SIG_WRAP *sig_wrap;

	sig_wrap = malloc(sizeof(OQS_SIG_WRAP));
    if (sig_wrap == NULL) {
        return NULL;
    }
    sig_wrap->pub_key_size = 0;
    sig_wrap->priv_key_size = 0;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        sig_wrap->sig = OQS_SIG_ml_dsa_44_new ();
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        sig_wrap->sig = OQS_SIG_ml_dsa_65_new ();
        break;
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        sig_wrap->sig = OQS_SIG_ml_dsa_87_new ();
        break;
    default:
        free (sig_wrap);
        return NULL;
    }

    return sig_wrap;
}

/**
 * Release the specified DSA context.
 *
 * @param[in]  dsa_context  Pointer to the DSA context to be released.
 **/
void libspdm_mldsa_free(void *dsa_context)
{
    OQS_SIG_WRAP *sig_wrap;

    sig_wrap = dsa_context;
    OQS_SIG_free (sig_wrap->sig);
    if (sig_wrap->priv_key_size != 0) {
        libspdm_zero_mem (sig_wrap->priv_key, sig_wrap->priv_key_size);
    }
    free (sig_wrap);
}

/**
 * Sets the key component into the established DSA context.
 *
 * @param[in, out]  dsa_context  Pointer to DSA context being set.
 * @param[in]       key_data     Pointer to octet integer buffer.
 * @param[in]       key_size     Size of big number buffer in bytes.
 *
 * @retval  true   DSA key component was set successfully.
 **/
bool libspdm_mldsa_set_pubkey(void *dsa_context, const uint8_t *key_data, size_t key_size)
{
    OQS_SIG_WRAP *sig_wrap;

    sig_wrap = dsa_context;
    LIBSPDM_ASSERT(key_size == sig_wrap->sig->length_public_key);
    if (key_size != sig_wrap->sig->length_public_key) {
        return false;
    }
    libspdm_copy_mem(sig_wrap->pub_key, sizeof(sig_wrap->pub_key), key_data, key_size);
    sig_wrap->pub_key_size = sig_wrap->sig->length_public_key;
    return true;
}

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
 * OID is defined in https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates
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

/**
 * Verifies the MLDSA signature.
 *
 * @param[in]  dsa_context   Pointer to DSA context for signature verification.
 * @param[in]  context       The MLDSA signing context.
 * @param[in]  context_size  Size of MLDSA signing context.
 * @param[in]  message       Pointer to octet message to be checked.
 * @param[in]  message_size  Size of the message in bytes.
 * @param[in]  signature     Pointer to DSA signature to be verified.
 * @param[in]  sig_size      Size of signature in bytes.
 *
 * @retval  true   Valid signature encoded.
 * @retval  false  Invalid signature or invalid DSA context.
 **/
bool libspdm_mldsa_verify(void *dsa_context,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t message_size,
                          const uint8_t *signature, size_t sig_size)
{
    OQS_STATUS rc;
    OQS_SIG_WRAP *sig_wrap;

    sig_wrap = dsa_context;
    LIBSPDM_ASSERT(sig_wrap->pub_key_size != 0);
    LIBSPDM_ASSERT(sig_size == sig_wrap->sig->length_signature);
    if (sig_wrap->pub_key_size == 0) {
        return false;
    }
    if (sig_size != sig_wrap->sig->length_signature) {
        return false;
    }
    rc = OQS_SIG_verify_with_ctx_str(sig_wrap->sig, message, message_size,
                                     signature, sig_size,
                                     context, context_size,
                                     sig_wrap->pub_key);
    if (rc != OQS_SUCCESS) {
        return false;
    }
    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
