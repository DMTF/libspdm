/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * Validate Crypto SLHDSA Interfaces.
 *
 * @retval  true   Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_slhdsa(void)
{
    void *slhdsa1;
    uint8_t message[] = "SlhDsaTest";
    uint8_t context[] = "SlhDsaContext";
    uint8_t signature1[49856];
    size_t sig1_size;
    uint8_t pub_key1[64];
    size_t pub_key1_size;
    bool status;
    void *slhdsa2;

    libspdm_my_print("\nCrypto SLH-DSA Signing Verification Testing:\n");

    libspdm_my_print("- Context1 ... ");
    slhdsa1 = libspdm_slhdsa_new(LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S);
    if (slhdsa1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    slhdsa2 = libspdm_slhdsa_new(LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S);
    if (slhdsa2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_slhdsa_free(slhdsa1);
        return false;
    }

    /* Verify SLH-DSA*/
    sig1_size = sizeof(signature1);
    libspdm_my_print("\n- SLH-DSA Signing ... ");
    status = libspdm_slhdsa_sign(slhdsa1, context, sizeof(context),
                                 message, sizeof(message),
                                 signature1, &sig1_size);
    if (!status || sig1_size != 7856) {
        libspdm_my_print("[Fail]");
        libspdm_slhdsa_free(slhdsa1);
        libspdm_slhdsa_free(slhdsa2);
        return false;
    }

    libspdm_my_print("SLH-DSA GetPubKey ... ");
    pub_key1_size = sizeof(pub_key1);
    status = libspdm_slhdsa_get_pubkey(slhdsa1, pub_key1, &pub_key1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_slhdsa_free(slhdsa1);
        libspdm_slhdsa_free(slhdsa2);
        return false;
    }

    libspdm_my_print("SLH-DSA SetPubKey ... ");
    status = libspdm_slhdsa_set_pubkey(slhdsa2, pub_key1, pub_key1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_slhdsa_free(slhdsa1);
        libspdm_slhdsa_free(slhdsa2);
        return false;
    }

    libspdm_my_print("SLH-DSA Verification ... ");
    status = libspdm_slhdsa_verify(slhdsa2, context, sizeof(context),
                                   message, sizeof(message),
                                   signature1, sig1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_slhdsa_free(slhdsa1);
        libspdm_slhdsa_free(slhdsa2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }
    libspdm_slhdsa_free(slhdsa1);
    libspdm_slhdsa_free(slhdsa2);

    return true;
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
