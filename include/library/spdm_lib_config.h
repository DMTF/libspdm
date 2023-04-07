/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_LIB_CONFIG_H
#define SPDM_LIB_CONFIG_H

/* Enables FIPS 140-3 mode. */
#ifndef LIBSPDM_FIPS_MODE
#define LIBSPDM_FIPS_MODE 0
#endif

/* Enables assertions and debug printing. When `LIBSPDM_DEBUG_ENABLE` is defined it overrides or
 * sets the values of `LIBSPDM_DEBUG_PRINT_ENABLE`, `LIBSPDM_DEBUG_ASSERT_ENABLE`, and
 * `LIBSPDM_BLOCK_ENABLE` to the value of `LIBSPDM_DEBUG_ENABLE`.
 *
 * Note that if this file is used with CMake and `DTARGET=Release` is defined, then all debugging
 * is disabled.
 */
#ifndef LIBSPDM_DEBUG_ENABLE
#define LIBSPDM_DEBUG_ENABLE 1
#endif

/* The SPDM specification allows a Responder to return up to 256 version entries in the `VERSION`
 * response to the Requester, including duplicate entries. For a Requester this value specifies the
 * maximum number of entries that libspdm will tolerate in a `VERSION` response before returning an
 * error. A similar macro, `SPDM_MAX_VERSION_COUNT`, exists for the Responder. However this macro
 * is not meant to be configured by the Integrator.
 */
#ifndef LIBSPDM_MAX_VERSION_COUNT
#define LIBSPDM_MAX_VERSION_COUNT 5
#endif

/* This value specifies the maximum size, in bytes, of the `PSK_EXCHANGE.RequesterContext` and,
 * if supported by the Responder, `PSK_EXCHANGE_RSP.ResponderContext` fields. The fields are
 * typically random or monotonically increasing numbers.
 */
#ifndef LIBSPDM_PSK_CONTEXT_LENGTH
#define LIBSPDM_PSK_CONTEXT_LENGTH LIBSPDM_MAX_HASH_SIZE
#endif
/* This value specifies the maximum size, in bytes, of the `PSK_EXCHANGE.PSKHint` field.*/
#ifndef LIBSPDM_PSK_MAX_HINT_LENGTH
#define LIBSPDM_PSK_MAX_HINT_LENGTH 16
#endif

/* libspdm allows an Integrator to specify multiple root certificates as trust anchors when
 * verifying certificate chains from an endpoint. This value specifies the maximum number of root
 * certificates that libspdm can support.
 */
#ifndef LIBSPDM_MAX_ROOT_CERT_SUPPORT
#define LIBSPDM_MAX_ROOT_CERT_SUPPORT 10
#endif

/* If the Responder supports it a Requester is allowed to establish multiple secure sessions with
 * the Responder. This value specifies the maximum number of sessions libspdm can support.
 */
#ifndef LIBSPDM_MAX_SESSION_COUNT
#define LIBSPDM_MAX_SESSION_COUNT 4
#endif
/* This value specifies the maximum size, in bytes, of a certificate chain that can be stored in a
 * libspdm context.
 */
#ifndef LIBSPDM_MAX_CERT_CHAIN_SIZE
#define LIBSPDM_MAX_CERT_CHAIN_SIZE 0x1000
#endif
#ifndef LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE
#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE 0x1000
#endif
/* Partial certificates can be retrieved from a Requester or Responder and through multiple messages
 * the complete certificate chain can be constructed. This value specifies the maximum size,
 * in bytes, of a partial certificate that can be sent or received.
 */
#ifndef LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
#define LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN 1024
#endif

#ifndef LIBSPDM_MAX_CSR_SIZE
#define LIBSPDM_MAX_CSR_SIZE 0x1000
#endif

/*
 * +--------------------------+------------------------------------------+---------+
 * | GET_VERSION              | 4                                        | 1       |
 * | VERSION {1.0, 1.1, 1.2}  | 6 + 2 * 3 = 12                           | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CAPABILITIES 1.2     | 20                                       | 1       |
 * | CAPABILITIES 1.2         | 20                                       | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | NEGOTIATE_ALGORITHMS 1.2 | 32 + 4 * 4 = 48                          | 2       |
 * | ALGORITHMS 1.2           | 36 + 4 * 4 = 52                          | 2       |
 * +--------------------------+------------------------------------------+---------+
 */
#define LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE (150 + 2 * LIBSPDM_MAX_VERSION_COUNT)

/*
 * +--------------------------+------------------------------------------+---------+
 * | GET_DIGESTS 1.2          | 4                                        | 1       |
 * | DIGESTS 1.2              | 4 + H * SlotNum = [36, 516]              | [1, 18] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CERTIFICATE 1.2      | 8                                        | 1       |
 * | CERTIFICATE 1.2          | 8 + PortionLen                           | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 */
#ifndef LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE (24 + \
                                           LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT + \
                                           LIBSPDM_MAX_CERT_CHAIN_SIZE)
#endif

/*
 * +--------------------------+------------------------------------------+---------+
 * | CHALLENGE 1.2            | 40                                       | 1       |
 * | CHALLENGE_AUTH 1.2       | 38 + H * 2 + S [+ O] = [166, 678]        | [6, 23] |
 * +--------------------------+------------------------------------------+---------+
 */
#ifndef LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE (78 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)
#endif

/*
 * +--------------------------+------------------------------------------+---------+
 * | GET_MEASUREMENTS 1.2     | 5 + Nonce (0 or 32)                      | 1       |
 * | MEASUREMENTS 1.2         | 42 + MeasRecLen (+ S) [+ O] = [106, 554] | [4, 19] |
 * +--------------------------+------------------------------------------+---------+
 */
#ifndef LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE (47 + SPDM_NONCE_SIZE + \
                                           LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE + SPDM_MAX_OPAQUE_DATA_SIZE)
#endif

/*
 * +--------------------------+------------------------------------------+---------+
 * | KEY_EXCHANGE 1.2         | 42 + D [+ O] = [106, 554]                | [4, 19] |
 * | KEY_EXCHANGE_RSP 1.2     | 42 + D + H + S (+ H) [+ O] = [234, 1194] | [8, 40] |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_EXCHANGE 1.2         | 12 [+ PSKHint] + R [+ O] = 44            | 2       |
 * | PSK_EXCHANGE_RSP 1.2     | 12 + R + H (+ H) [+ O] = [108, 172]      | [4, 6]  |
 * +--------------------------+------------------------------------------+---------+
 */
#ifndef LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE (84 + LIBSPDM_MAX_DHE_KEY_SIZE * 2 + \
                                           LIBSPDM_MAX_HASH_SIZE * 2 + LIBSPDM_MAX_ASYM_KEY_SIZE + \
                                           SPDM_MAX_OPAQUE_DATA_SIZE * 2)
#endif

/*
 * +--------------------------+------------------------------------------+---------+
 * | FINISH 1.2               | 4 (+ S) + H = [100, 580]                 | [4, 20] |
 * | FINISH_RSP 1.2           | 4 (+ H) = [36, 69]                       | [1, 3]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_FINISH 1.2           | 4 + H = [36, 68]                         | [1, 3]  |
 * | PSK_FINISH_RSP 1.2       | 4                                        | 1       |
 * +--------------------------+------------------------------------------+---------+
 */
#ifndef LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE (8 + LIBSPDM_MAX_HASH_SIZE * 2 + \
                                           LIBSPDM_MAX_ASYM_KEY_SIZE)
#endif

#ifndef LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_M_BUFFER_SIZE)
#endif

#ifndef LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_MESSAGE_B_BUFFER_SIZE + LIBSPDM_MAX_MESSAGE_C_BUFFER_SIZE)
#endif

#ifndef LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE
#define LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE \
    (LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_K_BUFFER_SIZE + \
     LIBSPDM_MAX_CERT_CHAIN_SIZE + LIBSPDM_MAX_MESSAGE_F_BUFFER_SIZE)
#endif

/* To ensure integrity in communication between the Requester and the Responder libspdm calculates
 * cryptographic digests and signatures over multiple requests and responses. This value specifies
 * whether libspdm will use a running calculation over the transcript, where requests and responses
 * are discarded as they are cryptographically consumed, or whether libspdm will buffer the entire
 * transcript before calculating the digest or signature.
 */
#ifndef LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 0
#endif


/* Cryptography Configuration
 * In each category, at least one should be selected.
 * NOTE: Not all combination can be supported. E.g. Don't mix NIST algo with SMx.*/

#ifndef LIBSPDM_RSA_SSA_SUPPORT
#define LIBSPDM_RSA_SSA_SUPPORT 1
#endif
#ifndef LIBSPDM_RSA_PSS_SUPPORT
#define LIBSPDM_RSA_PSS_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDSA_SUPPORT
#define LIBSPDM_ECDSA_SUPPORT 1
#endif
#ifndef LIBSPDM_SM2_DSA_SUPPORT
#define LIBSPDM_SM2_DSA_SUPPORT 1
#endif
#ifndef LIBSPDM_EDDSA_ED25519_SUPPORT
#define LIBSPDM_EDDSA_ED25519_SUPPORT 1
#endif
#ifndef LIBSPDM_EDDSA_ED448_SUPPORT
#define LIBSPDM_EDDSA_ED448_SUPPORT 1
#endif

#ifndef LIBSPDM_FFDHE_SUPPORT
#define LIBSPDM_FFDHE_SUPPORT 1
#endif
#ifndef LIBSPDM_ECDHE_SUPPORT
#define LIBSPDM_ECDHE_SUPPORT 1
#endif
#ifndef LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT
#define LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT 1
#endif

#ifndef LIBSPDM_AEAD_GCM_SUPPORT
#define LIBSPDM_AEAD_GCM_SUPPORT 1
#endif
#ifndef LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT
#define LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT 1
#endif
#ifndef LIBSPDM_AEAD_SM4_SUPPORT
#define LIBSPDM_AEAD_SM4_SUPPORT 1
#endif

#ifndef LIBSPDM_SHA256_SUPPORT
#define LIBSPDM_SHA256_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA384_SUPPORT
#define LIBSPDM_SHA384_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA512_SUPPORT
#define LIBSPDM_SHA512_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA3_256_SUPPORT
#define LIBSPDM_SHA3_256_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA3_384_SUPPORT
#define LIBSPDM_SHA3_384_SUPPORT 1
#endif
#ifndef LIBSPDM_SHA3_512_SUPPORT
#define LIBSPDM_SHA3_512_SUPPORT 1
#endif
#ifndef LIBSPDM_SM3_256_SUPPORT
#define LIBSPDM_SM3_256_SUPPORT 1
#endif

/* This can be set to 0 for the device which does not need X509 parser.*/
#ifndef LIBSPDM_CERT_PARSE_SUPPORT
#define LIBSPDM_CERT_PARSE_SUPPORT 1
#endif

/* Code space optimization for Optional request/response messages.*/

/* Consumers of libspdm may wish to not fully implement all of the optional
 * SPDM request/response messages. Therefore we have provided these
 * SPDM_ENABLE_CAPABILITY_***_CAP compile time switches as an optimization
 * disable the code (#if 0) related to said optional capability, thereby
 * reducing the code space used in the image.*/

/* A single switch may enable/disable a single capability or group of related
 * capabilities.*/

/* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP - Enable/Disable single CERT capability.
 * LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP - Enable/Disable single CHAL capability.
 * LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP - Enable/Disables multiple MEAS capabilities:
 *                                  (MEAS_CAP_NO_SIG, MEAS_CAP_SIG, MEAS_FRESH_CAP)*/

/* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP - Enable/Disable single Key Exchange capability.
 * LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP - Enable/Disable PSK_EX and PSK_FINISH.*/

/* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP - Enable/Disable mutual authentication.
* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP    - Enable/Disable encapsulated message.*/

/* LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP - Enable/Disable get csr capability.
 * LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP - Enable/Disable set certificate capability. */

#ifndef LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CERT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
#define LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
#define LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
#define LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#define LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#define LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP
#define LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
#define LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP 1
#endif

#ifndef LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
#define LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP 1
#endif

/* When LIBSPDM_RESPOND_IF_READY_SUPPORT is 0 then
 *      - For a Requester, if the Responder sends a ResponseNotReady ERROR response then the error
 *        is immediately returned to the Integrator. The Requester cannot send a RESPOND_IF_READY
 *        request.
 *      - For a Responder, it cannot send a RESPOND_IF_READY ERROR response and does not support
 *        RESPOND_IF_READY.
 * When LIBSPDM_RESPOND_IF_READY_SUPPORT is 1 then
 *      - For a Requester, if the Responder sends a ResponseNotReady ERROR response then libspdm
 *        waits an amount of time, as specified by the RDTExponent parameter, before sending
 *        RESPOND_IF_READY.
 *      - For a Responder, if its response state is NOT_READY then it will send a ResponseNotReady
 *        ERROR response to the Requester, and will accept a subsequent RESPOND_IF_READY request.
 */
#ifndef LIBSPDM_RESPOND_IF_READY_SUPPORT
#define LIBSPDM_RESPOND_IF_READY_SUPPORT 1
#endif

/*
 * MinDataTransferSize = 42
 *
 * H = HashLen = HmacLen = [32, 64]
 * S = SigLen = [64, 512]
 * D = ExchangeDataLen = [64, 512]
 * R = RequesterContextLen >= 32
 * R = ResponderContextLen >= 0
 * O = OpaqueDataLen <= 1024
 *
 * Max Chunk No = 1, if (message size <= 42)
 * Max Chunk No = [(message size + 4) / 30] roundup, if (message size > 42)
 *
 * +==========================+==========================================+=========+
 * |  Command                 |   Size                                   |MaxChunk |
 * +==========================+==========================================+=========+
 * | GET_VERSION              | 4                                        | 1       |
 * | VERSION {1.0, 1.1, 1.2}  | 6 + 2 * 3 = 12                           | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CAPABILITIES 1.2     | 20                                       | 1       |
 * | CAPABILITIES 1.2         | 20                                       | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | ERROR                    | 4                                        | 1       |
 * | ERROR(ResponseTooLarge)  | 4 + 4 = 8                                | 1       |
 * | ERROR(LargeResponse)     | 4 + 1 = 5                                | 1       |
 * | ERROR(ResponseNotReady)  | 4 + 4 = 8                                | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | CHUNK_SEND header        | 12 + L0 (0 or 4)                         | 1       |
 * | CHUNK_RESPONSE header    | 12 + L0 (0 or 4)                         | 1       |
 * +==========================+==========================================+=========+
 * | NEGOTIATE_ALGORITHMS 1.2 | 32 + 4 * 4 = 48                          | 2       |
 * | ALGORITHMS 1.2           | 36 + 4 * 4 = 52                          | 2       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_DIGESTS 1.2          | 4                                        | 1       |
 * | DIGESTS 1.2              | 4 + H * SlotNum = [36, 516]              | [1, 18] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CERTIFICATE 1.2      | 8                                        | 1       |
 * | CERTIFICATE 1.2          | 8 + PortionLen                           | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 * | CHALLENGE 1.2            | 40                                       | 1       |
 * | CHALLENGE_AUTH 1.2       | 38 + H * 2 + S [+ O] = [166, 678]        | [6, 23] |
 * +--------------------------+------------------------------------------+---------+
 * | GET_MEASUREMENTS 1.2     | 5 + Nonce (0 or 32)                      | 1       |
 * | MEASUREMENTS 1.2         | 42 + MeasRecLen (+ S) [+ O] = [106, 554] | [4, 19] |
 * +--------------------------+------------------------------------------+---------+
 * | KEY_EXCHANGE 1.2         | 42 + D [+ O] = [106, 554]                | [4, 19] |
 * | KEY_EXCHANGE_RSP 1.2     | 42 + D + H + S (+ H) [+ O] = [234, 1194] | [8, 40] |
 * +--------------------------+------------------------------------------+---------+
 * | FINISH 1.2               | 4 (+ S) + H = [100, 580]                 | [4, 20] |
 * | FINISH_RSP 1.2           | 4 (+ H) = [36, 69]                       | [1, 3]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_EXCHANGE 1.2         | 12 [+ PSKHint] + R [+ O] = 44            | 2       |
 * | PSK_EXCHANGE_RSP 1.2     | 12 + R + H (+ H) [+ O] = [108, 172]      | [4, 6]  |
 * +--------------------------+------------------------------------------+---------+
 * | PSK_FINISH 1.2           | 4 + H = [36, 68]                         | [1, 3]  |
 * | PSK_FINISH_RSP 1.2       | 4                                        | 1       |
 * +--------------------------+------------------------------------------+---------+
 * | GET_CSR 1.2              | 8 + RequesterInfoLen [+ O]               | [1, ]   |
 * | CSR 1.2                  | 8 + CSRLength                            | [1, ]   |
 * +--------------------------+------------------------------------------+---------+
 * | SET_CERTIFICATE 1.2      | 4 + CertChainLen                         | [1, ]   |
 * | SET_CERTIFICATE_RSP 1.2  | 4                                        | 1       |
 * +==========================+==========================================+=========+
 */

/* Required sender/receive buffer in device io.
 * NOTE: This is transport specific. Below configuration is just an example.
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 * | TYPE  |TransHdr|      EncryptionHeader     |AppHdr|  |Random|MAC|AlignPad|FINAL|
 * |       |        |SessionId|SeqNum|Len|AppLen|      |  |      |   |        |     |
 * +-------+--------+---------------------------+------+  +------+---+--------+-----+
 * | MCTP  |    1   |    4    |   2  | 2 |   2  |   1  |  |  32  | 12|   0    |  56 |
 * |PCI_DOE|    8   |    4    |   0  | 2 |   2  |   0  |  |   0  | 12|   3    |  31 |
 * +-------+--------+---------------------------+------+--+------+---+--------+-----+
 */
#ifndef LIBSPDM_TRANSPORT_ADDITIONAL_SIZE
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE    64
#endif
#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE (LIBSPDM_SENDER_BUFFER_SIZE - \
                                           LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE (LIBSPDM_RECEIVER_BUFFER_SIZE - \
                                             LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as LIBSPDM_DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than LIBSPDM_DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    #ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
    #define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
    #endif
#else
    #define LIBSPDM_MAX_SPDM_MSG_SIZE LIBSPDM_DATA_TRANSFER_SIZE
#endif

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

/* Enable message logging.
 * See https://github.com/DMTF/libspdm/blob/main/doc/user_guide.md#message-logging
 * for more information */
#ifndef LIBSPDM_ENABLE_MSG_LOG
#define LIBSPDM_ENABLE_MSG_LOG 1
#endif

/* Enable macro checking during compilation. */
#ifndef LIBSPDM_CHECK_MACRO
#define LIBSPDM_CHECK_MACRO 0
#endif

/* Enable checks to the SPDM context during runtime. */
#ifndef LIBSPDM_CHECK_SPDM_CONTEXT
#define LIBSPDM_CHECK_SPDM_CONTEXT 1
#endif

#endif /* SPDM_LIB_CONFIG_H */
