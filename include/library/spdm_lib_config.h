/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#ifndef __SPDM_LIB_CONFIG_H__
#define __SPDM_LIB_CONFIG_H__

#define DEFAULT_CONTEXT_LENGTH MAX_HASH_SIZE
#define DEFAULT_SECURE_MCTP_PADDING_SIZE 1

#define MAX_SPDM_PSK_HINT_LENGTH 16

#define MAX_SPDM_MEASUREMENT_BLOCK_COUNT 8
#define MAX_SPDM_SESSION_COUNT 4
#define MAX_SPDM_CERT_CHAIN_SIZE 0x1000
#define MAX_SPDM_MEASUREMENT_RECORD_SIZE 0x1000
#define MAX_SPDM_CERT_CHAIN_BLOCK_LEN 1024

#define MAX_SPDM_MESSAGE_BUFFER_SIZE 0x1200
#define MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE 0x100  // to hold message_a before negotiate
#define MAX_SPDM_MESSAGE_MEDIUM_BUFFER_SIZE 0x300 // to hold message_k before finished_key is ready

#define MAX_SPDM_REQUEST_RETRY_TIMES 3
#define MAX_SPDM_SESSION_STATE_CALLBACK_NUM 4
#define MAX_SPDM_CONNECTION_STATE_CALLBACK_NUM 4

// If cache transcript data or transcript hash
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 0

//
// Crypto Configuation
// In each category, at least one should be selected.
//
#define OPENSPDM_RSA_SSA_SUPPORT 1
#define OPENSPDM_RSA_PSS_SUPPORT 1
#define OPENSPDM_ECDSA_SUPPORT 1

#define OPENSPDM_FFDHE_SUPPORT 1
#define OPENSPDM_ECDHE_SUPPORT 1

#define OPENSPDM_AEAD_GCM_SUPPORT 1
#define OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 1

#define OPENSPDM_SHA256_SUPPORT 1
#define OPENSPDM_SHA384_SUPPORT 1
#define OPENSPDM_SHA512_SUPPORT 1

#endif
