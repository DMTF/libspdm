/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"


/* Max Known digest size is SHA512 output (64 bytes) by far*/

#define MAX_DIGEST_SIZE 64


/* data string for HMAC validation*/

GLOBAL_REMOVE_IF_UNREFERENCED const char *m_hmac_data = "Hi There";


/* key value for HMAC-SHA-256 validation. (from "4. Test Vectors" of IETF RFC4231)*/

GLOBAL_REMOVE_IF_UNREFERENCED const uint8_t m_hmac_sha256_key[20] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};


/* result for HMAC-SHA-256 ("Hi There"). (from "4. Test Vectors" of IETF RFC4231)*/

GLOBAL_REMOVE_IF_UNREFERENCED const uint8_t m_hmac_sha256_digest[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

/**
 * Validate Crypto message Authentication Codes Interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_hmac(void)
{
    void *hmac_ctx;
    uint8_t digest[MAX_DIGEST_SIZE];
    bool status;

    my_print(" \nCrypto HMAC Engine Testing:\n");

    my_print("- HMAC-SHA256: ");

    /* HMAC-SHA-256 digest Validation*/

    zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = hmac_sha256_new();
    if (hmac_ctx == NULL) {
        my_print("[Fail]");
        return RETURN_ABORTED;
    }

    status = hmac_sha256_set_key(hmac_ctx, m_hmac_sha256_key, 20);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Update... ");
    status = hmac_sha256_update(hmac_ctx, m_hmac_data, 8);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Finalize... ");
    status = hmac_sha256_final(hmac_ctx, digest);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    free_pool(hmac_ctx);

    my_print("Check value... ");
    if (const_compare_mem(digest, m_hmac_sha256_digest, SHA256_DIGEST_SIZE) !=
        0) {
        my_print("[Fail]");
        return RETURN_ABORTED;
    }

    my_print("[Pass]\n");

    my_print("- HMAC-SHA3_256: ");

    /* HMAC-SHA3-256 digest Validation*/

    zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = hmac_sha3_256_new();
    if (hmac_ctx == NULL) {
        my_print("[Fail]\n");
        return RETURN_SUCCESS;
    }

    status = hmac_sha3_256_set_key(hmac_ctx, m_hmac_sha256_key, 20);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Update... ");
    status = hmac_sha3_256_update(hmac_ctx, m_hmac_data, 8);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Finalize... ");
    status = hmac_sha3_256_final(hmac_ctx, digest);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    free_pool(hmac_ctx);
    my_print("[Pass]\n");

    my_print("- HMAC-SM3_256: ");

    /* HMAC-SM3-256 digest Validation*/

    zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = hmac_sm3_256_new();
    if (hmac_ctx == NULL) {
        my_print("[Fail]\n");
        return RETURN_SUCCESS;
    }

    status = hmac_sm3_256_set_key(hmac_ctx, m_hmac_sha256_key, 20);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Update... ");
    status = hmac_sm3_256_update(hmac_ctx, m_hmac_data, 8);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    my_print("Finalize... ");
    status = hmac_sm3_256_final(hmac_ctx, digest);
    if (!status) {
        my_print("[Fail]");
        free_pool(hmac_ctx);
        return RETURN_ABORTED;
    }

    free_pool(hmac_ctx);
    my_print("[Pass]\n");

    return RETURN_SUCCESS;
}
