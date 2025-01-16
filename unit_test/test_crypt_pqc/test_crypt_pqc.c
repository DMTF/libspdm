/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt_pqc.h"

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
bool libspdm_cryp_pqc_test_main(void)
{
    bool status;

    libspdm_my_print("\nCrypto PQC Wrapper Cryptosystem Testing: \n");
    libspdm_my_print("-------------------------------------------- \n");

    status = libspdm_validate_crypt_pqc_sig();
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_pqc_kem();
    if (!status) {
        return status;
    }

    return status;
}

int main(void)
{
    int return_value = 0;

    if (!libspdm_cryp_pqc_test_main()) {
        return_value = 1;
    }

    return return_value;
}
