/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_LIB_CONFIG_H__
#define __SPDM_LIB_CONFIG_H__

/* How many version entries in a VERSION response that a Requester will tolerate */
#define LIBSPDM_MAX_VERSION_COUNT 5

#define LIBSPDM_PSK_CONTEXT_LENGTH LIBSPDM_MAX_HASH_SIZE
#define LIBSPDM_PSK_MAX_HINT_LENGTH 16

#define LIBSPDM_MAX_MEASUREMENT_BLOCK_COUNT 8
#define LIBSPDM_MAX_SESSION_COUNT 4
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x1000
#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE 0x1000
#define LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 1024

#define LIBSPDM_MAX_MESSAGE_BUFFER_SIZE 0x1200
#define LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE 0x100  /* to hold message_a before negotiate*/
#define LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE 0x300 /* to hold message_k before finished_key is ready*/

#define LIBSPDM_MAX_REQUEST_RETRY_TIMES 3
#define LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM 4
#define LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM 4

/* If cache transcript data or transcript hash*/
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 0


/* Crypto Configuation*/
/* In each category, at least one should be selected.*/
/* NOTE: Not all combination can be supported. E.g. Don't mix NIST algo with SMx.*/

#define LIBSPDM_RSA_SSA_SUPPORT 1
#define LIBSPDM_RSA_PSS_SUPPORT 1
#define LIBSPDM_ECDSA_SUPPORT 1
#define LIBSPDM_SM2_DSA_SUPPORT 1
#define LIBSPDM_EDDSA_ED25519_SUPPORT 1
#define LIBSPDM_EDDSA_ED448_SUPPORT 1

#define LIBSPDM_FFDHE_SUPPORT 1
#define LIBSPDM_ECDHE_SUPPORT 1
#define LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT 1

#define LIBSPDM_AEAD_GCM_SUPPORT 1
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 1
#define LIBSPDM_AEAD_SM4_SUPPORT 1

#define LIBSPDM_SHA256_SUPPORT 1
#define LIBSPDM_SHA384_SUPPORT 1
#define LIBSPDM_SHA512_SUPPORT 1
#define LIBSPDM_SHA3_256_SUPPORT 1
#define LIBSPDM_SHA3_384_SUPPORT 1
#define LIBSPDM_SHA3_512_SUPPORT 1
#define LIBSPDM_SM3_256_SUPPORT 1


/* Code space optimization for Optional request/response messages.*/

/* Consumers of libspdm may wish to not fully implement all of the optional*/
/* SPDM request/response messages. Therefore we have provided these*/
/* SPDM_ENABLE_CAPABILITY_***_CAP compile time switches as an optimization*/
/* disable the code (#if 0) related to said optional capability, thereby*/
/* reducing the code space used in the image.*/

/* A single switch may enable/disable a single capability or group of related*/
/* capabilities.*/

/* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP - Enable/Disable single CERT capability.*/
/* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP - Enable/Disable single CHAL capability.*/
/* SPDM_ENABLE_CAPABILTIY_MEAS_CAP - Enable/Disables multiple MEAS capabilities:*/
/*                                  (MEAS_CAP_NO_SIG, MEAS_CAP_SIG, MEAS_FRESH_CAP)*/

/* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP - Enable/Disable single Key Exchange capability.*/
/* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP - Enable/Disable PSK_EX and PSK_FINISH.*/

#define LIBSPDM_ENABLE_CAPABILITY_CERT_CAP 1
#define LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP 1
#define LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP 1

#define LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP 1
#define LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP 1

#endif
