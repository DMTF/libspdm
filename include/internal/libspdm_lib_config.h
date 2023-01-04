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

#if defined(LIBSPDM_ENABLE_SET_CERTIFICATE_CAP) && \
    !defined(LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP)
#ifdef _MSC_VER
#pragma message("LIBSPDM_ENABLE_SET_CERTIFICATE_CAP is deprecated. Use " \
    "LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP instead. This warning will be removed in a " \
    "future release.")
#else
#warning LIBSPDM_ENABLE_SET_CERTIFICATE_CAP is deprecated. Use \
    LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP instead. This warning will be removed in a \
    future release.
#endif /* _MSC_VER */
#endif /* defined(LIBSPDM_ENABLE_SET_CERTIFICATE_CAP) */

#if defined(LIBSPDM_ENABLE_CHUNK_CAP) && !defined(LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP)
#ifdef _MSC_VER
#pragma message("LIBSPDM_ENABLE_CHUNK_CAP is deprecated. Use LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP " \
    "instead. This warning will be removed in a future release.")
#else
#warning LIBSPDM_ENABLE_CHUNK_CAP is deprecated. Use LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP \
    instead. This warning will be removed in a future release.
#endif /* _MSC_VER */
#endif /* defined(LIBSPDM_ENABLE_CHUNK_CAP) */

#if defined(MDEPKG_NDEBUG) && !defined(LIBSPDM_DEBUG_ENABLE)
#ifdef _MSC_VER
#pragma message("MDEPKG_NDEBUG is deprecated. Use LIBSPDM_DEBUG_ENABLE " \
    "instead. This warning will be removed in a future release.")
#else
#warning MDEPKG_NDEBUG is deprecated. Use LIBSPDM_DEBUG_ENABLE \
    instead. This warning will be removed in a future release.
#endif /* _MSC_VER */
#endif /* defined(MDEPKG_NDEBUG) */

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

/*when in FIPS mode, only support approved algo in FIPS */
#if LIBSPDM_FIPS_MODE
#undef LIBSPDM_SM2_DSA_SUPPORT
#define LIBSPDM_SM2_DSA_SUPPORT 0

#undef LIBSPDM_EDDSA_ED25519_SUPPORT
#define LIBSPDM_EDDSA_ED25519_SUPPORT 0

#undef LIBSPDM_EDDSA_ED448_SUPPORT
#define LIBSPDM_EDDSA_ED448_SUPPORT 0

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
