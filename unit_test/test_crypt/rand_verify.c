/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#define RANDOM_NUMBER_SIZE 256

uint8_t m_seed_string[] = "This is the random seed for PRNG verification.";

uint8_t m_previous_random_buffer[RANDOM_NUMBER_SIZE] = { 0x0 };

uint8_t m_random_buffer[RANDOM_NUMBER_SIZE] = { 0x0 };

/**
 * Validate Crypto pseudorandom number generator interfaces.
 *
 * @retval  RETURN_SUCCESS  Validation succeeded.
 * @retval  RETURN_ABORTED  Validation failed.
 *
 **/
return_status validate_crypt_prng(void)
{
    uintn index;
    bool status;

    my_print(" \nCrypto PRNG Engine Testing:\n");

    my_print("- Random Generation...");

    status = random_seed(m_seed_string, sizeof(m_seed_string));
    if (!status) {
        my_print("[Fail]");
        return RETURN_ABORTED;
    }

    for (index = 0; index < 10; index++) {
        status = random_bytes(m_random_buffer, RANDOM_NUMBER_SIZE);
        if (!status) {
            my_print("[Fail]");
            return RETURN_ABORTED;
        }

        if (const_compare_mem(m_previous_random_buffer, m_random_buffer,
                              RANDOM_NUMBER_SIZE) == 0) {
            my_print("[Fail]");
            return RETURN_ABORTED;
        }

        copy_mem_s(m_previous_random_buffer, sizeof(m_previous_random_buffer),
                   m_random_buffer, RANDOM_NUMBER_SIZE);
    }

    my_print("[Pass]\n");

    return RETURN_SUCCESS;
}
