/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef LIBSPDM_MACRO_CHECK_H
#define LIBSPDM_MACRO_CHECK_H

#define LIBSPDM_ASYM_ALGO_SUPPORT \
    ((LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) || (LIBSPDM_ECDSA_SUPPORT) || \
    (LIBSPDM_SM2_DSA_SUPPORT) || (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT))

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) && !LIBSPDM_ASYM_ALGO_SUPPORT
    #error If KEY_EX_CAP is enabled then at least one asymmetric algorithm must also be enabled.
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP) && !LIBSPDM_ASYM_ALGO_SUPPORT
    #error If CERT_CAP is enabled then at least one asymmetric algorithm must also be enabled.
#endif

#if (LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP) && !LIBSPDM_ASYM_ALGO_SUPPORT
    #error If CHAL_CAP is enabled then at least one asymmetric algorithm must also be enabled.
#endif

#endif /* LIBSPDM_MACRO_CHECK_H */