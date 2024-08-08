/**
 * SPDX-FileCopyrightText: 2021-2024 DMTF
 * SPDX-License-Identifier: BSD-3-Clause
 **/

/** @file
 * Provides random number generator services.
 **/

#ifndef __RNG_LIB_H__
#define __RNG_LIB_H__

/**
 * Generates a 64-bit random number.
 *
 * if rand is NULL, then ASSERT().
 *
 * @param[out] rand_data     buffer pointer to store the 64-bit random value.
 *
 * @retval true         Random number generated successfully.
 * @retval false        Failed to generate the random number.
 *
 **/
bool libspdm_get_random_number_64(uint64_t *rand_data);

#endif /* __RNG_LIB_H__*/
