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

char *m_test_kem_algo_name[] = {
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
};

/* Displays hexadecimal strings */
static void OQS_print_hex_string(const char *label, const uint8_t *str, size_t len) {
	printf("%-20s (%4zu bytes):  ", label, len);
	for (size_t i = 0; i < (len); i++) {
		printf("%02X", str[i]);
	}
	printf("\n");
}

typedef struct magic_s {
    uint8_t val[31];
} magic_t;

static OQS_STATUS kem_test_correctness(const char *method_name) {

    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;
    OQS_STATUS rc, ret = OQS_ERROR;
    int rv;

    //The magic numbers are random values.
    //The length of the magic number was chosen to be 31 to break alignment
    magic_t magic;
    OQS_randombytes(magic.val, sizeof(magic_t));

    kem = OQS_KEM_new(method_name);
    if (kem == NULL) {
        fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
        goto err;
    }

    printf("================================================================================\n");
    printf("Sample computation for KEM %s\n", kem->method_name);
    printf("================================================================================\n");

    public_key = malloc(kem->length_public_key + 2 * sizeof(magic_t));
    secret_key = malloc(kem->length_secret_key + 2 * sizeof(magic_t));
    ciphertext = malloc(kem->length_ciphertext + 2 * sizeof(magic_t));
    shared_secret_e = malloc(kem->length_shared_secret + 2 * sizeof(magic_t));
    shared_secret_d = malloc(kem->length_shared_secret + 2 * sizeof(magic_t));

    if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
        fprintf(stderr, "ERROR: malloc failed\n");
        goto err;
    }

    //Set the magic numbers before
    memcpy(public_key, magic.val, sizeof(magic_t));
    memcpy(secret_key, magic.val, sizeof(magic_t));
    memcpy(ciphertext, magic.val, sizeof(magic_t));
    memcpy(shared_secret_e, magic.val, sizeof(magic_t));
    memcpy(shared_secret_d, magic.val, sizeof(magic_t));

    public_key += sizeof(magic_t);
    secret_key += sizeof(magic_t);
    ciphertext += sizeof(magic_t);
    shared_secret_e += sizeof(magic_t);
    shared_secret_d += sizeof(magic_t);

    // and after
    memcpy(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
    memcpy(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
    memcpy(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
    memcpy(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
    memcpy(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));

    rc = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
        goto err;
    }

    OQS_TEST_CT_DECLASSIFY(public_key, kem->length_public_key);
    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
        goto err;
    }

    OQS_TEST_CT_DECLASSIFY(ciphertext, kem->length_ciphertext);
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
        goto err;
    }

    OQS_TEST_CT_DECLASSIFY(shared_secret_d, kem->length_shared_secret);
    OQS_TEST_CT_DECLASSIFY(shared_secret_e, kem->length_shared_secret);
    rv = memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret);
    if (rv != 0) {
        fprintf(stderr, "ERROR: shared secrets are not equal\n");
        OQS_print_hex_string("shared_secret_e", shared_secret_e, kem->length_shared_secret);
        OQS_print_hex_string("shared_secret_d", shared_secret_d, kem->length_shared_secret);
        goto err;
    } else {
        printf("shared secrets are equal\n");
    }

    // test invalid encapsulation (call should either fail or result in invalid shared secret)
    OQS_randombytes(ciphertext, kem->length_ciphertext);
    OQS_TEST_CT_DECLASSIFY(ciphertext, kem->length_ciphertext);
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    OQS_TEST_CT_DECLASSIFY(shared_secret_d, kem->length_shared_secret);
    OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
    if (rc == OQS_SUCCESS && memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps succeeded on wrong input\n");
        goto err;
    }

#ifndef OQS_ENABLE_TEST_CONSTANT_TIME
    rv = memcmp(public_key + kem->length_public_key, magic.val, sizeof(magic_t));
    rv |= memcmp(secret_key + kem->length_secret_key, magic.val, sizeof(magic_t));
    rv |= memcmp(ciphertext + kem->length_ciphertext, magic.val, sizeof(magic_t));
    rv |= memcmp(shared_secret_e + kem->length_shared_secret, magic.val, sizeof(magic_t));
    rv |= memcmp(shared_secret_d + kem->length_shared_secret, magic.val, sizeof(magic_t));
    rv |= memcmp(public_key - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(secret_key - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(ciphertext - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(shared_secret_e - sizeof(magic_t), magic.val, sizeof(magic_t));
    rv |= memcmp(shared_secret_d - sizeof(magic_t), magic.val, sizeof(magic_t));
    if (rv != 0) {
        fprintf(stderr, "ERROR: Magic numbers do not match\n");
        goto err;
    }
#endif

    ret = OQS_SUCCESS;
    goto cleanup;

err:
    ret = OQS_ERROR;

cleanup:
    if (secret_key) {
        OQS_MEM_secure_free(secret_key - sizeof(magic_t), kem->length_secret_key + 2 * sizeof(magic_t));
    }
    if (shared_secret_e) {
        OQS_MEM_secure_free(shared_secret_e - sizeof(magic_t), kem->length_shared_secret + 2 * sizeof(magic_t));
    }
    if (shared_secret_d) {
        OQS_MEM_secure_free(shared_secret_d - sizeof(magic_t), kem->length_shared_secret + 2 * sizeof(magic_t));
    }
    if (public_key) {
        OQS_MEM_insecure_free(public_key - sizeof(magic_t));
    }
    if (ciphertext) {
        OQS_MEM_insecure_free(ciphertext - sizeof(magic_t));
    }
    OQS_KEM_free(kem);

    return ret;
}

bool libspdm_validate_crypt_pqc_kem(void)
{
    OQS_STATUS rc;
    char *alg_name;
    size_t index;

    OQS_init();
    for (index = 0; index < LIBSPDM_ARRAY_SIZE(m_test_kem_algo_name); index++) {
        alg_name = m_test_kem_algo_name[index];
        rc = kem_test_correctness(alg_name);
        if (rc != OQS_SUCCESS) {
            OQS_destroy();
            return false;
        }
    }
    OQS_destroy();
    return true;
}
