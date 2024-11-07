// SPDX-License-Identifier: MIT

/** 
 * Version of liboqs as a string. Equivalent to {MAJOR}.{MINOR}.{PATCH}{PRE_RELEASE} 
 */
#define OQS_VERSION_TEXT "0.12.0"
/** 
 * Version levels of liboqs as integers.
 */
#define OQS_VERSION_MAJOR 0
#define OQS_VERSION_MINOR 12
#define OQS_VERSION_PATCH 0
/** 
 * OQS_VERSION_PRE_RELEASE is defined if this is a pre-release version of liboqs, otherwise it is undefined.
 * Examples: "-dev" or "-rc1".
 */
#define OQS_VERSION_PRE_RELEASE ""

#define OQS_COMPILE_BUILD_TARGET "AMD64-Windows-10.0.22631"
#define OQS_DIST_BUILD 1
#define OQS_DIST_X86_64_BUILD 1
/* #undef OQS_DIST_X86_BUILD */
/* #undef OQS_DIST_ARM64_V8_BUILD */
/* #undef OQS_DIST_ARM32_V7_BUILD */
/* #undef OQS_DIST_PPC64LE_BUILD */
#define OQS_DEBUG_BUILD 1
#define ARCH_X86_64 1
/* #undef ARCH_ARM64v8 */
/* #undef ARCH_ARM32v7 */
/* #undef BUILD_SHARED_LIBS */
/* #undef OQS_BUILD_ONLY_LIB */
#define OQS_OPT_TARGET "auto"
/* #undef USE_SANITIZER */
#define CMAKE_BUILD_TYPE "Debug"

/* #undef OQS_USE_OPENSSL */
/* #undef OQS_USE_AES_OPENSSL */
/* #undef OQS_USE_SHA2_OPENSSL */
/* #undef OQS_USE_SHA3_OPENSSL */
/* #undef OQS_DLOPEN_OPENSSL */
/* #undef OQS_OPENSSL_CRYPTO_SONAME */

/* #undef OQS_EMBEDDED_BUILD */

#define OQS_ENABLE_KEM_ML_KEM 1
#define OQS_ENABLE_KEM_ml_kem_512 1
/* #undef OQS_ENABLE_KEM_ml_kem_512_avx2 */
#define OQS_ENABLE_KEM_ml_kem_768 1
/* #undef OQS_ENABLE_KEM_ml_kem_768_avx2 */
#define OQS_ENABLE_KEM_ml_kem_1024 1
/* #undef OQS_ENABLE_KEM_ml_kem_1024_avx2 */

#define OQS_ENABLE_SIG_ML_DSA 1
#define OQS_ENABLE_SIG_ml_dsa_44 1
/* #undef OQS_ENABLE_SIG_ml_dsa_44_avx2 */
#define OQS_ENABLE_SIG_ml_dsa_65 1
/* #undef OQS_ENABLE_SIG_ml_dsa_65_avx2 */
#define OQS_ENABLE_SIG_ml_dsa_87 1
/* #undef OQS_ENABLE_SIG_ml_dsa_87_avx2 */
