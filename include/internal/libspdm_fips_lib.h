/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
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

/**
 * HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha256(void);
/**
 * HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha384(void);
/**
 * HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha512(void);

/**
 * AES_GCM self_test
 **/
bool libspdm_fips_selftest_aes_gcm(void);

/**
 * RSA_SSA(RSASSA-PKCS1 v1.5) self_test
 **/
bool libspdm_fips_selftest_rsa_ssa(void);

/**
 * HKDF KAT test
 **/
bool libspdm_fips_selftest_hkdf(void);

/**
 * ECDH self_test
 **/
bool libspdm_fips_selftest_ecdh(void);

/**
 * SHA256 KAT: HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_sha256(void);
/**
 * SHA384 KAT: HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_sha384(void);
/**
 * SHA512 KAT: HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_sha512(void);

/**
 * SHA3_256 KAT
 **/
bool libspdm_fips_selftest_sha3_256(void);
/**
 * SHA3_384 KAT
 **/
bool libspdm_fips_selftest_sha3_384(void);
/**
 * SHA3_512 KAT
 **/
bool libspdm_fips_selftest_sha3_512(void);

/**
 * FFDH self_test
 **/
bool libspdm_fips_selftest_ffdh(void);

/**
 * ECDSA self_test
 **/
bool libspdm_fips_selftest_ecdsa(void);

/**
 * EDDSA self_test
 **/
bool libspdm_fips_selftest_eddsa(void);

#endif/*LIBSPDM_FIPS_MODE*/
