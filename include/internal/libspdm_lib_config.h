/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef LIBSPDM_LIB_CONFIG_H
#define LIBSPDM_LIB_CONFIG_H

#ifndef LIBSPDM_CONFIG
#include "library/spdm_lib_config.h"
#else
#include LIBSPDM_CONFIG
#endif

#if defined(LIBSPDM_DEBUG_ENABLE)
#undef LIBSPDM_DEBUG_ASSERT_ENABLE
#undef LIBSPDM_DEBUG_PRINT_ENABLE
#undef LIBSPDM_DEBUG_BLOCK_ENABLE

#define LIBSPDM_DEBUG_ASSERT_ENABLE (LIBSPDM_DEBUG_ENABLE)
#define LIBSPDM_DEBUG_PRINT_ENABLE (LIBSPDM_DEBUG_ENABLE)
#define LIBSPDM_DEBUG_BLOCK_ENABLE (LIBSPDM_DEBUG_ENABLE)
#elif defined(MDEPKG_NDEBUG)
#undef LIBSPDM_DEBUG_ASSERT_ENABLE
#undef LIBSPDM_DEBUG_PRINT_ENABLE
#undef LIBSPDM_DEBUG_BLOCK_ENABLE

#define LIBSPDM_DEBUG_ASSERT_ENABLE 0
#define LIBSPDM_DEBUG_PRINT_ENABLE 0
#define LIBSPDM_DEBUG_BLOCK_ENABLE 0
#endif /* defined(LIBSPDM_DEBUG_ENABLE) */

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT

/*
 * +--------------------------+------------------------------------------+---------+
 * | GET_DIGESTS 1.2          | 4                                        | 1       |
 * | DIGESTS 1.2              | 4 + H * SlotNum = [36, 516]              | [1, 18] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CERTIFICATE 1.2      | 8                                        | 1       |
 * | CERTIFICATE 1.2          | 8 + PortionLen                           | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE (24 + \
                                           LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT + \
                                           LIBSPDM_MAX_CERT_CHAIN_SIZE)

/*
 * +--------------------------+------------------------------------------+---------+
 * | CHALLENGE 1.2            | 40                                       | 1       |
 * | CHALLENGE_AUTH 1.2       | 38 + H * 2 + S [+ O] = [166, 678]        | [6, 23] |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE (78 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)

/*
 * +--------------------------+------------------------------------------+---------+
 * | GET_MEASUREMENTS 1.2     | 5 + Nonce (0 or 32)                      | 1       |
 * | MEASUREMENTS 1.2         | 42 + MeasRecLen (+ S) [+ O] = [106, 554] | [4, 19] |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE (47 + SPDM_NONCE_SIZE + \
                                           LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)

/*
 * +--------------------------+------------------------------------------+---------+
 * | KEY_EXCHANGE 1.2         | 42 + D [+ O] = [106, 554]                | [4, 19] |
 * | KEY_EXCHANGE_RSP 1.2     | 42 + D + H + S (+ H) [+ O] = [234, 1194] | [8, 40] |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_EXCHANGE 1.2         | 12 [+ PSKHint] + R [+ O] = 44            | 2       |
 * | PSK_EXCHANGE_RSP 1.2     | 12 + R + H (+ H) [+ O] = [108, 172]      | [4, 6]  |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE (84 + LIBSPDM_MAX_DHE_KEY_SIZE * 2 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + LIBSPDM_MAX_ASYM_KEY_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE * 2)

/*
 * +--------------------------+------------------------------------------+---------+
 * | FINISH 1.2               | 4 (+ S) + H = [100, 580]                 | [4, 20] |
 * | FINISH_RSP 1.2           | 4 (+ H) = [36, 69]                       | [1, 3]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_FINISH 1.2           | 4 + H = [36, 68]                         | [1, 3]  |
 * | PSK_FINISH_RSP 1.2       | 4                                        | 1       |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE (8 + LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE)

#define LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE)

#define LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE)

#endif /* LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT */

/*when in FIPS mode, only support approved algo in FIPS */
#if LIBSPDM_FIPS_MODE
#undef LIBSPDM_SM2_DSA_SUPPORT
#define LIBSPDM_SM2_DSA_SUPPORT 0

#undef LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
#define LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT 0

#undef LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 0

#undef LIBSPDM_AEAD_SM4_SUPPORT
#define LIBSPDM_AEAD_SM4_SUPPORT 0

#undef LIBSPDM_SM3_256_SUPPORT
#define LIBSPDM_SM3_256_SUPPORT 0
#endif /*LIBSPDM_FIPS_MODE*/

#if LIBSPDM_CHECK_MACRO
#include "internal/libspdm_macro_check.h"
#endif /* LIBSPDM_CHECK_MACRO */

#endif /* LIBSPDM_LIB_CONFIG_H */
