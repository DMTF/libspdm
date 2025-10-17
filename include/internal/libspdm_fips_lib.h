/**
 *  Copyright Notice:
 *  Copyright 2023-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#if LIBSPDM_FIPS_MODE

#define LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256   0x00000001
#define LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384   0x00000002
#define LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512   0x00000004
#define LIBSPDM_FIPS_SELF_TEST_AES_GCM       0x00000008
#define LIBSPDM_FIPS_SELF_TEST_RSA_SSA       0x00000010
#define LIBSPDM_FIPS_SELF_TEST_HKDF          0x00000020
#define LIBSPDM_FIPS_SELF_TEST_ECDH          0x00000040
#define LIBSPDM_FIPS_SELF_TEST_SHA256        0x00000080
#define LIBSPDM_FIPS_SELF_TEST_SHA384        0x00000100
#define LIBSPDM_FIPS_SELF_TEST_SHA512        0x00000200
#define LIBSPDM_FIPS_SELF_TEST_SHA3_256      0x00000400
#define LIBSPDM_FIPS_SELF_TEST_SHA3_384      0x00000800
#define LIBSPDM_FIPS_SELF_TEST_SHA3_512      0x00001000
#define LIBSPDM_FIPS_SELF_TEST_FFDH          0x00002000
#define LIBSPDM_FIPS_SELF_TEST_ECDSA         0x00004000
#define LIBSPDM_FIPS_SELF_TEST_EDDSA         0x00008000
#define LIBSPDM_FIPS_SELF_TEST_RSA_PSS       0x00010000
#define LIBSPDM_FIPS_SELF_TEST_ML_KEM        0x00020000
#define LIBSPDM_FIPS_SELF_TEST_ML_DSA        0x00040000
#define LIBSPDM_FIPS_SELF_TEST_SLH_DSA       0x00080000

#if LIBSPDM_SLH_DSA_SUPPORT
#define LIBSPDM_FIPS_REQUIRED_BUFFER_SIZE 7856 /* SLH_DSA_SHA2_128S_SIG_SIZE */
#elif LIBSPDM_ML_DSA_SUPPORT
#define LIBSPDM_FIPS_REQUIRED_BUFFER_SIZE 4627 /* ML_DSA_87_SIG_SIZE */
#elif LIBSPDM_ML_KEM_SUPPORT
#define LIBSPDM_FIPS_REQUIRED_BUFFER_SIZE 1568 /* ML_KEM_1024_CT_SIZE */
#else
#define LIBSPDM_FIPS_REQUIRED_BUFFER_SIZE 0
#endif

/**
 * HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha256(void *fips_selftest_context);
/**
 * HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha384(void *fips_selftest_context);
/**
 * HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha512(void *fips_selftest_context);

/**
 * AES_GCM self_test
 **/
bool libspdm_fips_selftest_aes_gcm(void *fips_selftest_context);

/**
 * RSA_SSA(RSASSA-PKCS1 v1.5) self_test
 **/
bool libspdm_fips_selftest_rsa_ssa(void *fips_selftest_context);

/**
 * RSA_PSS self_test
 **/
bool libspdm_fips_selftest_rsa_pss(void *fips_selftest_context);

/**
 * HKDF KAT test
 **/
bool libspdm_fips_selftest_hkdf(void *fips_selftest_context);

/**
 * ECDH self_test
 **/
bool libspdm_fips_selftest_ecdh(void *fips_selftest_context);

/**
 * SHA256 KAT: HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_sha256(void *fips_selftest_context);
/**
 * SHA384 KAT: HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_sha384(void *fips_selftest_context);
/**
 * SHA512 KAT: HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_sha512(void *fips_selftest_context);

/**
 * SHA3_256 KAT
 **/
bool libspdm_fips_selftest_sha3_256(void *fips_selftest_context);
/**
 * SHA3_384 KAT
 **/
bool libspdm_fips_selftest_sha3_384(void *fips_selftest_context);
/**
 * SHA3_512 KAT
 **/
bool libspdm_fips_selftest_sha3_512(void *fips_selftest_context);

/**
 * FFDH self_test
 **/
bool libspdm_fips_selftest_ffdh(void *fips_selftest_context);

/**
 * ECDSA self_test
 **/
bool libspdm_fips_selftest_ecdsa(void *fips_selftest_context);

/**
 * EDDSA self_test
 **/
bool libspdm_fips_selftest_eddsa(void *fips_selftest_context);

/**
 * ML-KEM self_test
 **/
bool libspdm_fips_selftest_mlkem(void *fips_selftest_context);

/**
 * ML-DSA self_test
 **/
bool libspdm_fips_selftest_mldsa(void *fips_selftest_context);

/**
 * SLH-DSA self_test
 **/
bool libspdm_fips_selftest_slhdsa(void *fips_selftest_context);

#endif/*LIBSPDM_FIPS_MODE*/
