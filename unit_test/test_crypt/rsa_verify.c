/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#define LIBSPDM_RSA_MODULUS_LENGTH 512


/* RSA PKCS#1 Validation data from OpenSSL "Fips_rsa_selftest.c"*/



/* public Modulus of RSA key*/

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_rsa_n[] = {
    0xBB, 0xF8, 0x2F, 0x09, 0x06, 0x82, 0xCE, 0x9C, 0x23, 0x38, 0xAC, 0x2B,
    0x9D, 0xA8, 0x71, 0xF7, 0x36, 0x8D, 0x07, 0xEE, 0xD4, 0x10, 0x43, 0xA4,
    0x40, 0xD6, 0xB6, 0xF0, 0x74, 0x54, 0xF5, 0x1F, 0xB8, 0xDF, 0xBA, 0xAF,
    0x03, 0x5C, 0x02, 0xAB, 0x61, 0xEA, 0x48, 0xCE, 0xEB, 0x6F, 0xCD, 0x48,
    0x76, 0xED, 0x52, 0x0D, 0x60, 0xE1, 0xEC, 0x46, 0x19, 0x71, 0x9D, 0x8A,
    0x5B, 0x8B, 0x80, 0x7F, 0xAF, 0xB8, 0xE0, 0xA3, 0xDF, 0xC7, 0x37, 0x72,
    0x3E, 0xE6, 0xB4, 0xB7, 0xD9, 0x3A, 0x25, 0x84, 0xEE, 0x6A, 0x64, 0x9D,
    0x06, 0x09, 0x53, 0x74, 0x88, 0x34, 0xB2, 0x45, 0x45, 0x98, 0x39, 0x4E,
    0xE0, 0xAA, 0xB1, 0x2D, 0x7B, 0x61, 0xA5, 0x1F, 0x52, 0x7A, 0x9A, 0x41,
    0xF6, 0xC1, 0x68, 0x7F, 0xE2, 0x53, 0x72, 0x98, 0xCA, 0x2A, 0x8F, 0x59,
    0x46, 0xF8, 0xE5, 0xFD, 0x09, 0x1D, 0xBD, 0xCB
};


/* public Exponent of RSA key*/

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_rsa_e[] = { 0x11 };


/* Private Exponent of RSA key*/

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_rsa_d[] = {
    0xA5, 0xDA, 0xFC, 0x53, 0x41, 0xFA, 0xF2, 0x89, 0xC4, 0xB9, 0x88, 0xDB,
    0x30, 0xC1, 0xCD, 0xF8, 0x3F, 0x31, 0x25, 0x1E, 0x06, 0x68, 0xB4, 0x27,
    0x84, 0x81, 0x38, 0x01, 0x57, 0x96, 0x41, 0xB2, 0x94, 0x10, 0xB3, 0xC7,
    0x99, 0x8D, 0x6B, 0xC4, 0x65, 0x74, 0x5E, 0x5C, 0x39, 0x26, 0x69, 0xD6,
    0x87, 0x0D, 0xA2, 0xC0, 0x82, 0xA9, 0x39, 0xE3, 0x7F, 0xDC, 0xB8, 0x2E,
    0xC9, 0x3E, 0xDA, 0xC9, 0x7F, 0xF3, 0xAD, 0x59, 0x50, 0xAC, 0xCF, 0xBC,
    0x11, 0x1C, 0x76, 0xF1, 0xA9, 0x52, 0x94, 0x44, 0xE5, 0x6A, 0xAF, 0x68,
    0xC5, 0x6C, 0x09, 0x2C, 0xD3, 0x8D, 0xC3, 0xBE, 0xF5, 0xD2, 0x0A, 0x93,
    0x99, 0x26, 0xED, 0x4F, 0x74, 0xA1, 0x3E, 0xDD, 0xFB, 0xE1, 0xA1, 0xCE,
    0xCC, 0x48, 0x94, 0xAF, 0x94, 0x28, 0xC2, 0xB7, 0xB8, 0x88, 0x3F, 0xE4,
    0x46, 0x3A, 0x4B, 0xC8, 0x5B, 0x1C, 0xB3, 0xC1
};


/* Known Answer Test (KAT) data for RSA PKCS#1 Signing*/

GLOBAL_REMOVE_IF_UNREFERENCED const char m_libspdm_rsa_sign_data[] =
    "OpenSSL FIPS 140-2 public key RSA KAT";


/* Known signature for the above message, under SHA-1 digest*/

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_rsa_pkcs1_signature[] = {
    0x71, 0xEE, 0x1A, 0xC0, 0xFE, 0x01, 0x93, 0x54, 0x79, 0x5C, 0xF2, 0x4C,
    0x4A, 0xFD, 0x1A, 0x05, 0x8F, 0x64, 0xB1, 0x6D, 0x61, 0x33, 0x8D, 0x9B,
    0xE7, 0xFD, 0x60, 0xA3, 0x83, 0xB5, 0xA3, 0x51, 0x55, 0x77, 0x90, 0xCF,
    0xDC, 0x22, 0x37, 0x8E, 0xD0, 0xE1, 0xAE, 0x09, 0xE3, 0x3D, 0x1E, 0xF8,
    0x80, 0xD1, 0x8B, 0xC2, 0xEC, 0x0A, 0xD7, 0x6B, 0x88, 0x8B, 0x8B, 0xA1,
    0x20, 0x22, 0xBE, 0x59, 0x5B, 0xE0, 0x23, 0x24, 0xA1, 0x49, 0x30, 0xBA,
    0xA9, 0x9E, 0xE8, 0xB1, 0x8A, 0x62, 0x16, 0xBF, 0x4E, 0xCA, 0x2E, 0x4E,
    0xBC, 0x29, 0xA8, 0x67, 0x13, 0xB7, 0x9F, 0x1D, 0x04, 0x44, 0xE5, 0x5F,
    0x35, 0x07, 0x11, 0xBC, 0xED, 0x19, 0x37, 0x21, 0xCF, 0x23, 0x48, 0x1F,
    0x72, 0x05, 0xDE, 0xE6, 0xE8, 0x7F, 0x33, 0x8A, 0x76, 0x4B, 0x2F, 0x95,
    0xDF, 0xF1, 0x5F, 0x84, 0x80, 0xD9, 0x46, 0xB4
};


/* Default public key 0x10001 = 65537*/

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_default_public_key[] = { 0x01, 0x00,
                                                                         0x01 };

/**
 * Validate Crypto RSA Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status libspdm_validate_crypt_rsa(void)
{
    void *rsa;
    uint8_t hash_value[LIBSPDM_SHA256_DIGEST_SIZE];
    uintn hash_size;
    void *sha256_ctx;
    uint8_t *signature;
    uintn sig_size;
    bool status;
    uintn key_size;
    uint8_t *KeyBuffer;

    libspdm_my_print("\nCrypto RSA Engine Testing: ");


    /* Generate & Initialize RSA context*/

    rsa = libspdm_rsa_new();
    libspdm_my_print("\n- Generate RSA context ... ");
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return RETURN_ABORTED;
    }


    /* Set/Get RSA key Components*/

    libspdm_my_print("Set/Get RSA key Components ... ");


    /* Set/Get RSA key N*/

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = 0;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, NULL, &key_size);
    if (status || key_size != sizeof(m_libspdm_rsa_n)) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, &key_size);
    if (!status || key_size != sizeof(m_libspdm_rsa_n)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (const_compare_mem(KeyBuffer, m_libspdm_rsa_n, key_size) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    free_pool(KeyBuffer);


    /* Set/Get RSA key E*/

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = 0;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, NULL, &key_size);
    if (status || key_size != sizeof(m_libspdm_rsa_e)) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, KeyBuffer, &key_size);
    if (!status || key_size != sizeof(m_libspdm_rsa_e)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (const_compare_mem(KeyBuffer, m_libspdm_rsa_e, key_size) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    free_pool(KeyBuffer);


    /* Clear/Get RSA key Components*/

    libspdm_my_print("Clear/Get RSA key Components ... ");


    /* Clear/Get RSA key N*/

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = 1;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, NULL, &key_size);
    if (!status || key_size != 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }


    /* Clear/Get RSA key E*/

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = 1;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, NULL, &key_size);
    if (!status || key_size != 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }


    /* Generate RSA key Components*/

    libspdm_my_print("Generate RSA key Components ... ");

    status = libspdm_rsa_generate_key(rsa, LIBSPDM_RSA_MODULUS_LENGTH, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, KeyBuffer, &key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (key_size != 3 ||
        const_compare_mem(KeyBuffer, m_libspdm_default_public_key, 3) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, &key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (key_size != LIBSPDM_RSA_MODULUS_LENGTH / 8) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (!libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }


    /* Check invalid RSA key components*/

    libspdm_my_print("Check Invalid RSA key Components ... ");

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (!libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    free_pool(KeyBuffer);


    /* SHA-256 digest message for PKCS#1 signature*/

    libspdm_my_print("hash Original message ... ");
    hash_size = LIBSPDM_SHA256_DIGEST_SIZE;
    zero_mem(hash_value, hash_size);
    sha256_ctx = libspdm_sha256_new();
    if (sha256_ctx == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_sha256_init(sha256_ctx);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_sha256_update(sha256_ctx, m_libspdm_rsa_sign_data,
                                   libspdm_ascii_str_len(m_libspdm_rsa_sign_data));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_sha256_final(sha256_ctx, hash_value);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    libspdm_sha256_free(sha256_ctx);


    /* Sign RSA PKCS#1-encoded signature*/

    libspdm_my_print("PKCS#1 signature ... ");

    libspdm_rsa_free(rsa);

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_D, m_libspdm_rsa_d, sizeof(m_libspdm_rsa_d));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    sig_size = 0;
    status = libspdm_rsa_pkcs1_sign_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                             hash_size, NULL, &sig_size);
    if (status || sig_size == 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    signature = allocate_pool(sig_size);
    if (signature == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }
    status = libspdm_rsa_pkcs1_sign_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                             hash_size, signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    if (sig_size != sizeof(m_libspdm_rsa_pkcs1_signature)) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }


    /* Verify RSA PKCS#1-encoded signature*/


    libspdm_my_print("PKCS#1 signature Verification ... ");

    status = libspdm_rsa_pkcs1_verify_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                               hash_size, signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        free_pool(signature);
        return RETURN_ABORTED;
    }

    free_pool(signature);


    /* Sign RSA PSS-encoded signature*/

    libspdm_my_print("PSS signature ... ");

    libspdm_rsa_free(rsa);

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_D, m_libspdm_rsa_d, sizeof(m_libspdm_rsa_d));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    sig_size = 0;
    status = libspdm_rsa_pss_sign(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  NULL, &sig_size);
    if (status || sig_size == 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    signature = allocate_pool(sig_size);
    if (signature == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }
    status = libspdm_rsa_pss_sign(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }


    /* Verify RSA PSS-encoded signature*/


    libspdm_my_print("PSS signature Verification ... ");

    status = libspdm_rsa_pss_verify(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                    signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return RETURN_ABORTED;
    }

    free_pool(signature);

    /* Release Resources*/

    libspdm_rsa_free(rsa);
    libspdm_my_print("Release RSA context ... [Pass]");

    libspdm_my_print("\n");

    return RETURN_SUCCESS;
}
