/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if LIBSPDM_ML_KEM_SUPPORT

/**
 * Validate Crypto MLKEM Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_mlkem(void)
{
    void *mlkem1;
    void *mlkem2;
    bool status;
    uint8_t encap_key1[1568];
    size_t encap_key1_length;
    uint8_t cipher_text2[1568];
    size_t cipher_text2_length;
    uint8_t shared_secret1[32];
    size_t shared_secret1_length;
    uint8_t shared_secret2[32];
    size_t shared_secret2_length;

    libspdm_my_print("\nCrypto ML-KEM Engine Testing:\n");

    encap_key1_length = sizeof(encap_key1);
    cipher_text2_length = sizeof(cipher_text2);
    shared_secret1_length = sizeof(shared_secret1);
    shared_secret2_length = sizeof(shared_secret2);
    libspdm_my_print("- Context1 ... ");
    mlkem1 = libspdm_mlkem_new_by_name(LIBSPDM_CRYPTO_NID_ML_KEM_512);
    if (mlkem1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    mlkem2 = libspdm_mlkem_new_by_name(LIBSPDM_CRYPTO_NID_ML_KEM_512);
    if (mlkem2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        return false;
    }

    libspdm_my_print("Generate encap key1 ... ");
    status = libspdm_mlkem_generate_key(mlkem1, encap_key1, &encap_key1_length);
    if (!status || encap_key1_length != 800) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        libspdm_dh_free(mlkem2);
        return false;
    }

    libspdm_my_print("Encapsulate shared secret2 ... ");
    status = libspdm_mlkem_encapsulate(mlkem2, encap_key1, encap_key1_length,
                                       cipher_text2, &cipher_text2_length,
                                       shared_secret2, &shared_secret2_length);
    if (!status || cipher_text2_length != 768 || shared_secret2_length != 32) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        libspdm_dh_free(mlkem2);
        return false;
    }

    libspdm_my_print("Decapsulate shared secret1 ... ");
    status = libspdm_mlkem_decapsulate(mlkem1, cipher_text2, cipher_text2_length,
                                       shared_secret1, &shared_secret1_length);
    if (!status || shared_secret1_length != 32) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        libspdm_dh_free(mlkem2);
        return false;
    }

    libspdm_my_print("Compare Keys ... ");
    if (shared_secret1_length != shared_secret2_length) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        libspdm_dh_free(mlkem2);
        return false;
    }

    if (memcmp(shared_secret1, shared_secret2, shared_secret1_length) != 0) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(mlkem1);
        libspdm_dh_free(mlkem2);
        return false;
    }

    libspdm_my_print("[Pass]\n");
    libspdm_dh_free(mlkem1);
    libspdm_dh_free(mlkem2);

    return true;
}

#endif /* LIBSPDM_ML_KEM_SUPPORT */
