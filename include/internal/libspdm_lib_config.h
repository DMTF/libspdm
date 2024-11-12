/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
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
#endif /* defined(LIBSPDM_DEBUG_ENABLE) */

/*when in FIPS mode, only support approved algo in FIPS */
#if LIBSPDM_FIPS_MODE
#undef LIBSPDM_SM2_DSA_P256_SUPPORT
#define LIBSPDM_SM2_DSA_P256_SUPPORT 0

#undef LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT
#define LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT 0

#undef LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 0

#undef LIBSPDM_AEAD_SM4_128_GCM_SUPPORT
#define LIBSPDM_AEAD_SM4_128_GCM_SUPPORT 0

#undef LIBSPDM_SM3_256_SUPPORT
#define LIBSPDM_SM3_256_SUPPORT 0
#endif /*LIBSPDM_FIPS_MODE*/

/* define crypto algorithm without parameter */
#define LIBSPDM_RSA_SSA_SUPPORT ((LIBSPDM_RSA_SSA_2048_SUPPORT) || \
                                 (LIBSPDM_RSA_SSA_3072_SUPPORT) || \
                                 (LIBSPDM_RSA_SSA_4096_SUPPORT))

#define LIBSPDM_RSA_PSS_SUPPORT ((LIBSPDM_RSA_PSS_2048_SUPPORT) || \
                                 (LIBSPDM_RSA_PSS_3072_SUPPORT) || \
                                 (LIBSPDM_RSA_PSS_4096_SUPPORT))

#define LIBSPDM_ECDSA_SUPPORT ((LIBSPDM_ECDSA_P256_SUPPORT) || \
                               (LIBSPDM_ECDSA_P384_SUPPORT) || \
                               (LIBSPDM_ECDSA_P521_SUPPORT))

#define LIBSPDM_SM2_DSA_SUPPORT (LIBSPDM_SM2_DSA_P256_SUPPORT)

#define LIBSPDM_EDDSA_SUPPORT ((LIBSPDM_EDDSA_ED25519_SUPPORT) || \
                               (LIBSPDM_EDDSA_ED448_SUPPORT))

#define LIBSPDM_FFDHE_SUPPORT ((LIBSPDM_FFDHE_2048_SUPPORT) || \
                               (LIBSPDM_FFDHE_3072_SUPPORT) || \
                               (LIBSPDM_FFDHE_4096_SUPPORT))

#define LIBSPDM_ECDHE_SUPPORT ((LIBSPDM_ECDHE_P256_SUPPORT) || \
                               (LIBSPDM_ECDHE_P384_SUPPORT) || \
                               (LIBSPDM_ECDHE_P521_SUPPORT))

#define LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT (LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT)

#define LIBSPDM_AEAD_GCM_SUPPORT ((LIBSPDM_AEAD_AES_128_GCM_SUPPORT) || \
                                  (LIBSPDM_AEAD_AES_256_GCM_SUPPORT))

#define LIBSPDM_AEAD_SM4_SUPPORT (LIBSPDM_AEAD_SM4_128_GCM_SUPPORT)

#define LIBSPDM_SHA2_SUPPORT ((LIBSPDM_SHA256_SUPPORT) || \
                              (LIBSPDM_SHA384_SUPPORT) || \
                              (LIBSPDM_SHA512_SUPPORT))

#define LIBSPDM_SHA3_SUPPORT ((LIBSPDM_SHA3_256_SUPPORT) || \
                              (LIBSPDM_SHA3_384_SUPPORT) || \
                              (LIBSPDM_SHA3_512_SUPPORT))

#define LIBSPDM_SM3_SUPPORT (LIBSPDM_SM3_256_SUPPORT)

#define LIBSPDM_ML_DSA_SUPPORT ((LIBSPDM_ML_DSA_44_SUPPORT) || \
                                (LIBSPDM_ML_DSA_65_SUPPORT) || \
                                (LIBSPDM_ML_DSA_87_SUPPORT))

#define LIBSPDM_SLH_DSA_SUPPORT ((LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT) || \
                                 (LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT))

#define LIBSPDM_ML_KEM_SUPPORT ((LIBSPDM_ML_KEM_512_SUPPORT) || \
                                (LIBSPDM_ML_KEM_768_SUPPORT) || \
                                (LIBSPDM_ML_KEM_1024_SUPPORT))

#if LIBSPDM_CHECK_MACRO
#include "internal/libspdm_macro_check.h"
#endif /* LIBSPDM_CHECK_MACRO */

#endif /* LIBSPDM_LIB_CONFIG_H */
