/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

size_t libspdm_ascii_str_len(const char *string)
{
    size_t length;

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
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%s", message));
}

/**
 * entrypoint of Cryptographic Validation Utility.
 **/
void libspdm_cryptest_main(void)
{
    bool status;

    libspdm_my_print("\nCrypto Wrapper Cryptosystem Testing: \n");
    libspdm_my_print("-------------------------------------------- \n");

    status = libspdm_validate_crypt_digest();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_hmac();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_hkdf();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_aead_cipher();
    if (!status) {
        return;
    }

    #if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    status = libspdm_validate_crypt_rsa();
    if (!status) {
        return;
    }
    #endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

    #if LIBSPDM_RSA_SSA_SUPPORT
    status = libspdm_validate_crypt_rsa_2();
    if (!status) {
        return;
    }
    #endif /* LIBSPDM_RSA_SSA_SUPPORT */

    status = libspdm_validate_crypt_x509("ecp256", sizeof("ecp256"));
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_x509("ecp384", sizeof("ecp384"));
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_x509("rsa2048", sizeof("rsa2048"));
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_x509("rsa3072", sizeof("rsa3072"));
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_dh();
    if (!status) {
        return;
    }

    #if LIBSPDM_ECDSA_SUPPORT
    status = libspdm_validate_crypt_ec();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_ec_2();
    if (!status) {
        return;
    }
    #endif /* LIBSPDM_ECDSA_SUPPORT */

    #if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
    status = libspdm_validate_crypt_ecd();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_ecd_2();
    if (!status) {
        return;
    }
    #endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

    #if LIBSPDM_SM2_DSA_SUPPORT
    status = libspdm_validate_crypt_sm2();
    if (!status) {
        return;
    }

    status = libspdm_validate_crypt_sm2_2();
    if (!status) {
        return;
    }
    #endif /* LIBSPDM_SM2_DSA_SUPPORT */

    status = libspdm_validate_crypt_prng();
    if (!status) {
        return;
    }

    #if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP
    status = libspdm_validate_crypt_x509_csr();
    if (!status) {
        return;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP **/

    return;
}

int main(void)
{
    libspdm_cryptest_main();
    return 0;
}
