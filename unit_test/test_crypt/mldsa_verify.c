/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * Validate Crypto MLDSA Interfaces.
 *
 * @retval  true   Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_mldsa(void)
{
    void *mldsa1;
    uint8_t message[] = "MlDsaTest";
    uint8_t context[] = "MlDsaContext";
    uint8_t signature1[4627];
    size_t sig1_size;
    uint8_t pub_key1[2592];
    size_t pub_key1_size;
    bool status;
    void *mldsa2;

    libspdm_my_print("\nCrypto ML-DSA Signing Verification Testing:\n");

    libspdm_my_print("- Context1 ... ");
    mldsa1 = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_44);
    if (mldsa1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    mldsa2 = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_44);
    if (mldsa2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_mldsa_free(mldsa1);
        return false;
    }

    /* Verify ML-DSA*/
    sig1_size = sizeof(signature1);
    libspdm_my_print("\n- ML-DSA Signing ... ");
    status = libspdm_mldsa_sign(mldsa1, context, sizeof(context),
                                message, sizeof(message),
                                signature1, &sig1_size);
    if (!status || sig1_size != 2420) {
        libspdm_my_print("[Fail]");
        libspdm_mldsa_free(mldsa1);
        libspdm_mldsa_free(mldsa2);
        return false;
    }

    libspdm_my_print("ML-DSA GetPubKey ... ");
    pub_key1_size = sizeof(pub_key1);
    status = libspdm_mldsa_get_pubkey(mldsa1, pub_key1, &pub_key1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_mldsa_free(mldsa1);
        libspdm_mldsa_free(mldsa2);
        return false;
    }

    libspdm_my_print("ML-DSA SetPubKey ... ");
    status = libspdm_mldsa_set_pubkey(mldsa2, pub_key1, pub_key1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_mldsa_free(mldsa1);
        libspdm_mldsa_free(mldsa2);
        return false;
    }

    libspdm_my_print("ML-DSA Verification ... ");
    status = libspdm_mldsa_verify(mldsa2, context, sizeof(context),
                                  message, sizeof(message),
                                  signature1, sig1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_mldsa_free(mldsa1);
        libspdm_mldsa_free(mldsa2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }
    libspdm_mldsa_free(mldsa1);
    libspdm_mldsa_free(mldsa2);

    return true;
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */
