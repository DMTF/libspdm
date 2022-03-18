/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

uintn libspdm_ascii_str_len(const char *string)
{
    uintn length;

    LIBSPDM_ASSERT(string != NULL);
    if (string == NULL) {
        return 0;
    }

    for (length = 0; *string != '\0'; string++, length++) {
        ;
    }
    return length;
}

void libspdm_my_print(const char *message)
{
    libspdm_debug_print(LIBSPDM_DEBUG_INFO, "%s", message);
}

/**
 * entrypoint of Cryptographic Validation Utility.
 *
 * @retval RETURN_SUCCESS       The entry point is executed successfully.
 * @retval other             Some error occurs when executing this entry point.
 *
 **/
return_status libspdm_cryptest_main(void)
{
    return_status status;

    libspdm_my_print("\nCrypto Wrapper Cryptosystem Testing: \n");
    libspdm_my_print("-------------------------------------------- \n");

    libspdm_random_seed(NULL, 0);

    status = libspdm_validate_crypt_digest();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_hmac();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_hkdf();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_aead_cipher();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_rsa();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_rsa_2();
    if (RETURN_ERROR(status)) {
        return status;
    }

    // skip ecp
    // status = libspdm_validate_crypt_x509("ecp256", sizeof("ecp256"));
    // if (RETURN_ERROR(status)) {
    //     return status;
    // }

    // status = libspdm_validate_crypt_x509("ecp384", sizeof("ecp384"));
    // if (RETURN_ERROR(status)) {
    //     return status;
    // }

    status = libspdm_validate_crypt_x509("rsa2048", sizeof("rsa2048"));
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_x509("rsa3072", sizeof("rsa3072"));
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_dh();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_ec();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_ec_2();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_ecd();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_ecd_2();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_ecx();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_sm2();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_sm2_2();
    if (RETURN_ERROR(status)) {
        return status;
    }

    status = libspdm_validate_crypt_prng();
    if (RETURN_ERROR(status)) {
        return status;
    }

    return RETURN_SUCCESS;
}

int main(void)
{
    libspdm_cryptest_main();
    return 0;
}
