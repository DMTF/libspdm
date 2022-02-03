/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "crypto/rand.h"
#include <openssl/aes.h>

#include <base.h>
#include "library/rnglib.h"

/**
 * Calls RandomNumber64 to fill
 * a buffer of arbitrary size with random bytes.
 * This is a shim layer to rnglib.
 *
 * @param[in]   length        size of the buffer, in bytes,  to fill with.
 * @param[out]  RandBuffer    Pointer to the buffer to store the random result.
 *
 * @retval true        Random bytes generation succeeded.
 * @retval false       Failed to request random bytes.
 *
 **/
static bool rand_get_bytes(IN uintn length, OUT uint8_t *RandBuffer)
{
    bool ret;
    uint64_t temp_rand;

    ret = false;

    if (RandBuffer == NULL) {
        DEBUG((DEBUG_ERROR,
               "[OPENSSL_RAND_POOL] NULL RandBuffer. No random numbers are generated and your system is not secure\n"));
        ASSERT(RandBuffer !=
               NULL); /* Since we can't generate random numbers, we should assert. Otherwise we will just blow up later.*/
        return ret;
    }

    while (length > 0) {
        /* Use rnglib to get random number*/
        ret = get_random_number_64(&temp_rand);

        if (!ret) {
            return ret;
        }
        if (length >= sizeof(temp_rand)) {
            *((uint64_t *)RandBuffer) = temp_rand;
            RandBuffer += sizeof(uint64_t);
            length -= sizeof(temp_rand);
        } else {
            copy_mem(RandBuffer, &temp_rand, length);
            length = 0;
        }
    }

    return ret;
}

/*
 * Add random bytes to the pool to acquire requested amount of entropy
 *
 * This function is platform specific and tries to acquire the requested
 * amount of entropy by polling platform specific entropy sources.
 *
 * This is OpenSSL required interface.
 */
size_t rand_pool_acquire_entropy(RAND_POOL *pool)
{
    bool ret;
    size_t Bytes_needed;
    unsigned char *buffer;

    Bytes_needed = rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    if (Bytes_needed > 0) {
        buffer = rand_pool_add_begin(pool, Bytes_needed);

        if (buffer != NULL) {
            ret = rand_get_bytes(Bytes_needed, buffer);
            if (false == ret) {
                rand_pool_add_end(pool, 0, 0);
            } else {
                rand_pool_add_end(pool, Bytes_needed,
                                  8 * Bytes_needed);
            }
        }
    }

    return rand_pool_entropy_available(pool);
}

/*
 * This is OpenSSL required interface.
 */
int rand_pool_add_nonce_data(RAND_POOL *pool)
{
    uint8_t data[16];
    rand_get_bytes(sizeof(data), data);

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

/*
 * This is OpenSSL required interface.
 */
int rand_pool_add_additional_data(RAND_POOL *pool)
{
    uint8_t data[16];
    rand_get_bytes(sizeof(data), data);

    return rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

/*
 * Dummy Implementation
 *
 * This is OpenSSL required interface.
 */
int rand_pool_init(void)
{
    return 1;
}

/*
 * Dummy Implementation
 *
 * This is OpenSSL required interface.
 */
void rand_pool_cleanup(void)
{
}

/*
 * Dummy Implementation
 *
 * This is OpenSSL required interface.
 */
void rand_pool_keep_random_devices_open(int keep)
{
}
