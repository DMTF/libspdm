/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#include "hal/library/debuglib.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"
#include "hal/library/cryptlib.h"

#include "oqs/oqs.h"

/* https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates */

/* OID definition */

uint8_t m_mldsa44_oid[] = {
    /* 2.16.840.1.101.3.4.3.17 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
};

uint8_t m_mldsa65_oid[] = {
    /* 2.16.840.1.101.3.4.3.18 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
};

uint8_t m_mldsa87_oid[] = {
    /* 2.16.840.1.101.3.4.3.19 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
};

/* DER template */
uint8_t m_mldsa44_der_header[] = {
    0x30, 0x82, 0x05, 0x32, /* 0x30=sequence (0x0532 byte) */
          0x30, 0x0b, /* 0x30=sequence (0x0b byte) */
                0x06, 0x09, /* 0x06=OID (0x09 byte) */
                    /* 2.16.840.1.101.3.4.3.17 */
                    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
          0x03, 0x82, 0x05, 0x21, /* 0x03=bit_string (0x0521 byte = pubkey size + 1) */
                0x00, /* pad head */
};

uint8_t m_mldsa65_der_header[] = {
    0x30, 0x82, 0x07, 0xb2, /* 0x30=sequence (0x07b2 byte) */
          0x30, 0x0b, /* 0x30=sequence (0x0b byte) */
                0x06, 0x09, /* 0x06=OID (0x09 byte) */
                    /* 2.16.840.1.101.3.4.3.18 */
                    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
          0x03, 0x82, 0x07, 0xa1, /* 0x03=bit_string (0x0721 byte = pubkey size + 1) */
                0x00, /* pad head */
};

uint8_t m_mldsa87_der_header[] = {
    0x30, 0x82, 0x0a, 0x32, /* 0x30=sequence (0x0a32 byte) */
          0x30, 0x0b, /* 0x30=sequence (0x0b byte) */
                0x06, 0x09, /* 0x06=OID (0x09 byte) */
                    /* 2.16.840.1.101.3.4.3.19 */
                    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
          0x03, 0x82, 0x0a, 0x21, /* 0x03=bit_string (0x0a21 byte = pubkey size + 1) */
                0x00, /* pad head */
};

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);

typedef struct {
    char *algo_name;
    char *dir_name;
    uint8_t *der_header;
    size_t der_header_size;
} pqc_sig_algo_struct_t;

pqc_sig_algo_struct_t m_pqc_sig_algo_strct[] = {
    {"ML-DSA-44", "mldsa44", m_mldsa44_der_header, sizeof(m_mldsa44_der_header)},
    {"ML-DSA-65", "mldsa65", m_mldsa65_der_header, sizeof(m_mldsa65_der_header)},
    {"ML-DSA-87", "mldsa87", m_mldsa87_der_header, sizeof(m_mldsa87_der_header)},
};

static OQS_STATUS libspdm_gen_pqc_key(const pqc_sig_algo_struct_t *method)
{
    OQS_SIG *sig = NULL;
    uint8_t *public_key = NULL;
    uint8_t *public_key_der = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *message = NULL;
    size_t message_len = 100;
    uint8_t *signature = NULL;
    size_t signature_len;
    OQS_STATUS rc, ret = OQS_ERROR;
    char file_name[256];
    bool res;

    sig = OQS_SIG_new(method->algo_name);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
        goto err;
    }

    printf("================================================================================\n");
    printf("Sample computation for signature %s\n", sig->method_name);
    printf("================================================================================\n");

    public_key = malloc(sig->length_public_key);
    public_key_der = malloc(sig->length_public_key + method->der_header_size);
    secret_key = malloc(sig->length_secret_key);
    message = malloc(message_len);
    signature = malloc(sig->length_signature);

    if ((public_key == NULL) || (public_key_der == NULL) || (secret_key == NULL) ||
        (message == NULL) || (signature == NULL)) {
        fprintf(stderr, "ERROR: malloc failed\n");
        goto err;
    }

    OQS_randombytes(message, message_len);

    rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
        goto err;
    }
    memcpy (public_key_der, method->der_header, method->der_header_size);
    memcpy (public_key_der + method->der_header_size, public_key, sig->length_public_key);
    assert (public_key_der[3] == (uint8_t)(sig->length_public_key + 18));
    assert (public_key_der[2] == (uint8_t)((sig->length_public_key + 18) >> 8));
    assert (public_key_der[20] == (uint8_t)(sig->length_public_key + 1));
    assert (public_key_der[19] == (uint8_t)((sig->length_public_key + 1) >> 8));

    rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
        goto err;
    }

    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
        goto err;
    }

    /* modify the signature to invalidate it */
    OQS_randombytes(signature, signature_len);
    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    if (rc != OQS_ERROR) {
        fprintf(stderr, "ERROR: OQS_SIG_verify should have failed!\n");
        goto err;
    }

    printf("verification passes as expected\n");
    ret = OQS_SUCCESS;

    strcpy (file_name, method->algo_name);
    strcat (file_name, ".key.priv.raw");
    res = libspdm_write_output_file (file_name, secret_key, sig->length_secret_key);
    if (!res) {
        fprintf(stderr, "ERROR: fail to write priv.key!\n");
        goto err;
    }
    printf("generate - %s\n", file_name);

    strcpy (file_name, method->algo_name);
    strcat (file_name, ".key.pub.raw");
    res = libspdm_write_output_file (file_name, public_key, sig->length_public_key);
    if (!res) {
        fprintf(stderr, "ERROR: fail to write pub.key!\n");
        goto err;
    }
    printf("generate - %s\n", file_name);

    strcpy (file_name, method->algo_name);
    strcat (file_name, ".key.pub.der");
    res = libspdm_write_output_file (file_name, public_key_der, sig->length_public_key + method->der_header_size);
    if (!res) {
        fprintf(stderr, "ERROR: fail to write pub.der!\n");
        goto err;
    }
    printf("generate - %s\n", file_name);

    goto cleanup;

err:
    ret = OQS_ERROR;

cleanup:
    if (secret_key) {
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
    }
    if (public_key) {
        OQS_MEM_insecure_free(public_key);
    }
    if (public_key_der) {
        OQS_MEM_insecure_free(public_key_der);
    }
    if (message) {
        OQS_MEM_insecure_free(message);
    }
    if (signature) {
        OQS_MEM_insecure_free(signature);
    }
    OQS_SIG_free(sig);

    return ret;
}

bool libspdm_gen_pqc_keys(void)
{
    OQS_STATUS rc;
    size_t index;

    printf("gen_pqc_keys...\n");

    OQS_init();
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pqc_sig_algo_strct); index++) {
        rc = libspdm_gen_pqc_key(&m_pqc_sig_algo_strct[index]);
        if (rc != OQS_SUCCESS) {
            OQS_destroy();
            return false;
        }
    }
    OQS_destroy();
    return true;
}

static bool libspdm_get_priv_pub_key_from_der(OQS_SIG *sig,
                                              const uint8_t *der_data,
                                              size_t der_size,
                                              const uint8_t **priv_key,
                                              const uint8_t **pub_key)
{
    size_t nid;
    const uint8_t *key_data;
    size_t key_size;
    uint8_t *ptr;
    uint8_t *end;
    size_t obj_len;
    bool ret;
    size_t priv_key_size;

    ptr = (uint8_t*)(size_t)der_data;
    obj_len = 0;
    end = ptr + der_size;

    /* SEQUENCE */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!ret) {
        return false;
    }

    /* INTEGER */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!ret) {
        return false;
    }
    ptr += obj_len;

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
    } else if ((obj_len == sizeof(m_mldsa65_oid)) &&
        libspdm_consttime_is_mem_equal (ptr, m_mldsa65_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_65;
    } else if ((obj_len == sizeof(m_mldsa87_oid)) &&
        libspdm_consttime_is_mem_equal (ptr, m_mldsa87_oid, obj_len)) {
        nid = LIBSPDM_CRYPTO_NID_ML_DSA_87;
    } else {
        return false;
    }
    ptr += obj_len;

    priv_key_size = sig->length_secret_key;
    key_size = sig->length_secret_key + sig->length_public_key;

    /* PrivKey OCTET STGRING */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OCTET_STRING);
    if (!ret) {
        return false;
    }

    /* PrivKey OCTET STGRING (1st - for hybrid) */
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OCTET_STRING);
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

    *priv_key = key_data;
    *pub_key = key_data + priv_key_size;

    return true;
}

static OQS_STATUS libspdm_derive_pqc_key(const pqc_sig_algo_struct_t *method)
{
    OQS_SIG *sig = NULL;
    OQS_STATUS ret;
    char file_name[256];
    bool res;
    void *file_data = NULL;
    size_t file_size;
    const uint8_t *priv_key;
    const uint8_t *pub_key;
    uint8_t *pub_key_der = NULL;
    size_t index;
    char *key_name[] = {
        "end_requester.key",
        "end_responder.key",
    };

    sig = OQS_SIG_new(method->algo_name);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
        goto err;
    }

    pub_key_der = malloc(method->der_header_size + sig->length_public_key);
    if (pub_key_der == NULL) {
        fprintf(stderr, "ERROR: malloc failed\n");
        goto err;
    }

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(key_name); index++) {
        sprintf (file_name, "../../unit_test/sample_key/%s/%s.der", method->dir_name, key_name[index]);
        res = libspdm_read_input_file(file_name, &file_data, &file_size);
        if (!res) {
            fprintf(stderr, "ERROR: fail to read %s/%s.der!\n", method->dir_name, key_name[index]);
            goto err;
        }
        res = libspdm_get_priv_pub_key_from_der (sig, file_data, file_size, &priv_key, &pub_key);
        if (!res) {
            fprintf(stderr, "ERROR: fail to get_priv_pub_key_from_der %s/%s.der!\n", method->dir_name, key_name[index]);
            goto err;
        }

        sprintf (file_name, "../../unit_test/sample_key/%s/%s.priv.raw", method->dir_name, key_name[index]);
        res = libspdm_write_output_file(file_name, priv_key, sig->length_secret_key);
        if (!res) {
            fprintf(stderr, "ERROR: fail to write %s/%s.priv.raw!\n", method->dir_name, key_name[index]);
            goto err;
        }
        printf("generate - %s\n", file_name);

        sprintf (file_name, "../../unit_test/sample_key/%s/%s.pub.raw", method->dir_name, key_name[index]);
        res = libspdm_write_output_file(file_name, pub_key, sig->length_public_key);
        if (!res) {
            fprintf(stderr, "ERROR: fail to write %s/%s.pub.raw!\n", method->dir_name, key_name[index]);
            goto err;
        }
        printf("generate - %s\n", file_name);

        memcpy (pub_key_der, method->der_header, method->der_header_size);
        memcpy (pub_key_der + method->der_header_size, pub_key, sig->length_public_key);
        assert (pub_key_der[3] == (uint8_t)(sig->length_public_key + 18));
        assert (pub_key_der[2] == (uint8_t)((sig->length_public_key + 18) >> 8));
        assert (pub_key_der[20] == (uint8_t)(sig->length_public_key + 1));
        assert (pub_key_der[19] == (uint8_t)((sig->length_public_key + 1) >> 8));
        sprintf (file_name, "../../unit_test/sample_key/%s/%s.pub.der", method->dir_name, key_name[index]);
        res = libspdm_write_output_file(file_name, pub_key_der, method->der_header_size + sig->length_public_key);
        if (!res) {
            fprintf(stderr, "ERROR: fail to write %s/%s.pub.der!\n", method->dir_name, key_name[index]);
            goto err;
        }
        printf("generate - %s\n", file_name);

        free(file_data);
        file_data = NULL;
    }

    ret = OQS_SUCCESS;
    goto cleanup;
err:
    ret = OQS_ERROR;
cleanup:
    if (file_data != NULL) {
        free(file_data);
    }
    if (pub_key_der != NULL) {
        free(pub_key_der);
    }
    OQS_SIG_free(sig);
    return ret;
}

bool libspdm_derive_pqc_keys(void)
{
    OQS_STATUS rc;
    size_t index;

    printf("derive_pqc_keys...\n");

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_pqc_sig_algo_strct); index++) {
        rc = libspdm_derive_pqc_key(&m_pqc_sig_algo_strct[index]);
        if (rc != OQS_SUCCESS) {
            return false;
        }
    }
    return true;
}

int main(void)
{
    int return_value = 0;

    if (!libspdm_derive_pqc_keys()) {
        if (!libspdm_gen_pqc_keys()) {
            return_value = 1;
        }
    }

    return return_value;
}