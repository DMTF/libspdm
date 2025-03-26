/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt_pqc.h"

#ifdef OQS_ENABLE_TEST_CONSTANT_TIME
#include <valgrind/memcheck.h>
#define OQS_TEST_CT_CLASSIFY(addr, len)  VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#define OQS_TEST_CT_DECLASSIFY(addr, len)  VALGRIND_MAKE_MEM_DEFINED(addr, len)
#else
#define OQS_TEST_CT_CLASSIFY(addr, len)
#define OQS_TEST_CT_DECLASSIFY(addr, len)
#endif

char *m_test_sig_algo_name[] = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
};

typedef struct magic_s {
    uint8_t val[31];
} magic_t;

static OQS_STATUS sig_test_correctness(const char *method_name) {

    OQS_SIG *sig = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *message = NULL;
    size_t message_len = 100;
    uint8_t *signature = NULL;
    size_t signature_len;
    OQS_STATUS rc, ret = OQS_ERROR;

    //The magic numbers are random values.
    //The length of the magic number was chosen to be 31 to break alignment
    magic_t magic;
    OQS_randombytes(magic.val, sizeof(magic_t));

    sig = OQS_SIG_new(method_name);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
        goto err;
    }

    printf("================================================================================\n");
    printf("Sample computation for signature %s\n", sig->method_name);
    printf("================================================================================\n");

    public_key = malloc(sig->length_public_key + 2 * sizeof(magic_t));
    secret_key = malloc(sig->length_secret_key + 2 * sizeof(magic_t));
    message = malloc(message_len + 2 * sizeof(magic_t));
    signature = malloc(sig->length_signature + 2 * sizeof(magic_t));

    if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
        fprintf(stderr, "ERROR: malloc failed\n");
        goto err;
    }

    //Set the magic numbers before
    memcpy(public_key, magic.val, sizeof(magic_t));
    memcpy(secret_key, magic.val, sizeof(magic_t));
    memcpy(message, magic.val, sizeof(magic_t));
    memcpy(signature, magic.val, sizeof(magic_t));

    public_key += sizeof(magic_t);
    secret_key += sizeof(magic_t);
    message += sizeof(magic_t);
    signature += sizeof(magic_t);

    // and after
    memcpy(public_key + sig->length_public_key, magic.val, sizeof(magic_t));
    memcpy(secret_key + sig->length_secret_key, magic.val, sizeof(magic_t));
    memcpy(message + message_len, magic.val, sizeof(magic_t));
    memcpy(signature + sig->length_signature, magic.val, sizeof(magic_t));

    OQS_randombytes(message, message_len);
    OQS_TEST_CT_DECLASSIFY(message, message_len);

    rc = OQS_SIG_keypair(sig, public_key, secret_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
        goto err;
    }

    rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
        goto err;
    }

    OQS_TEST_CT_DECLASSIFY(public_key, sig->length_public_key);
    OQS_TEST_CT_DECLASSIFY(signature, signature_len);
    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
        goto err;
    }

    /* modify the signature to invalidate it */
    OQS_randombytes(signature, signature_len);
    OQS_TEST_CT_DECLASSIFY(signature, signature_len);
    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_ERROR) {
        fprintf(stderr, "ERROR: OQS_SIG_verify should have failed!\n");
        goto err;
    }

#ifndef OQS_ENABLE_TEST_CONSTANT_TIME
    /* check magic values */
    int rv = memcmp(public_key + sig->length_public_key, magic.val, sizeof(magic_t));
    rv |= memcmp(secret_key + sig->length_secret_key, magic.val, sizeof(magic_t));
    rv |= memcmp(message + message_len, magic.val, sizeof(magic_t));
    rv |= memcmp(signature + sig->length_signature, magic.val, sizeof(magic_t));
    rv |= memcmp(public_key - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(secret_key - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(message - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(signature - sizeof(magic_t), magic.val, sizeof(magic_t));
    if (rv) {
        fprintf(stderr, "ERROR: Magic numbers do not mtach\n");
        goto err;
    }
#endif

    printf("verification passes as expected\n");
    ret = OQS_SUCCESS;
    goto cleanup;

err:
    ret = OQS_ERROR;

cleanup:
    if (secret_key) {
        OQS_MEM_secure_free(secret_key - sizeof(magic_t), sig->length_secret_key + 2 * sizeof(magic_t));
    }
    if (public_key) {
        OQS_MEM_insecure_free(public_key - sizeof(magic_t));
    }
    if (message) {
        OQS_MEM_insecure_free(message - sizeof(magic_t));
    }
    if (signature) {
        OQS_MEM_insecure_free(signature - sizeof(magic_t));
    }
    OQS_SIG_free(sig);

    return ret;
}

bool libspdm_validate_crypt_pqc_sig(void)
{
    OQS_STATUS rc;
    char *alg_name;
    size_t index;

    OQS_init();
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_test_sig_algo_name); index++) {
        alg_name = m_test_sig_algo_name[index];
        rc = sig_test_correctness(alg_name);
        if (rc != OQS_SUCCESS) {
            OQS_destroy();
            return false;
        }
    }
    OQS_destroy();
    return true;
}
