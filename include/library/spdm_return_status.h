/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_RETURN_STATUS_H
#define SPDM_RETURN_STATUS_H

#include <stdint.h>

/** The layout of libspdm_return_t is
 * [31:28] - severity
 * [27:24] - reserved
 * [23:16] - source
 * [15:00] - code
 **/
/* TODO: Change to uint32_t once conversion has completed */
typedef size_t libspdm_return_t;

/* Returns 1 if severity is LIBSPDM_SEVERITY_SUCCESS else it returns 0. */
#define LIBSPDM_STATUS_IS_SUCCESS(status) \
    (LIBSPDM_STATUS_SEVERITY(status) == LIBSPDM_SEVERITY_SUCCESS)

/* Returns 1 if severity is LIBSPDM_SEVERITY_ERROR else it returns 0. */
#define LIBSPDM_STATUS_IS_ERROR(status) \
    (LIBSPDM_STATUS_SEVERITY(status) == LIBSPDM_SEVERITY_ERROR)

/* Returns the severity of the status. */
#define LIBSPDM_STATUS_SEVERITY(status) (((status) >> 28) &0xf)

/* Returns the source of the status. */
#define LIBSPDM_STATUS_SOURCE(status) (((status) >> 16) & 0xff)

#define LIBSPDM_SEVERITY_SUCCESS 0x0
#define LIBSPDM_SEVERITY_ERROR 0x8

#define LIBSPDM_SOURCE_SUCCESS 0x00
#define LIBSPDM_SOURCE_CORE 0x01
#define LIBSPDM_SOURCE_CRYPTO 0x02
#define LIBSPDM_SOURCE_CERT_PARSE 0x03
#define LIBSPSM_SOURCE_TRANSPORT 0x04
#define LIBSPDM_SOURCE_MEAS_COLLECT 0x05
#define LIBSPDM_SOURCE_RNG 0x06

#define LIBSPDM_STATUS_CONSTRUCT(severity, source, code) \
    ((libspdm_return_t)(((severity) << 28) | ((source) << 16) | (code)))

/* Success status is always 0x00000000. */
#define LIBSPDM_STATUS_SUCCESS \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_SUCCESS, LIBSPDM_SOURCE_SUCCESS, 0x0000)

#define LIBSPDM_RET_ON_ERR(status) \
    do { \
        if (LIBSPDM_STATUS_IS_ERROR(status)) { \
            return (status); \
        } \
    } \
    while (0)

/* Core errors. */

/* Unable to complete operation due to unsupported capabilities by either the caller, the peer,
 * or both. */
#define LIBSPDM_STATUS_UNSUPPORTED_CAP \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0002)

/* Unable to complete operation due to caller's state. */
#define LIBSPDM_STATUS_INVALID_STATE_LOCAL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0003)

/* Unable to complete operation due to peer's state. */
#define LIBSPDM_STATUS_INVALID_STATE_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0004)

/* The received message contains one or more invalid message fields. */
#define LIBSPDM_STATUS_INVALID_MSG_FIELD \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0005)

/* The received message's size is invalid. */
#define LIBSPDM_STATUS_INVALID_MSG_SIZE \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0006)

/* Unable to derive a common set of versions, algorithms, etc. */
#define LIBSPDM_STATUS_NEGOTIATION_FAIL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0007)

/* Received a Busy error message. */
#define LIBSPDM_STATUS_BUSY_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0008)

/* Received an unexpected error message. */
#define LIBSPDM_STATUS_ERROR_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0009)

/* Received a RequestResynch error message. */
#define LIBSPDM_STATUS_RESYNCH_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x000a)

/* Unable to append new data to buffer due to resource exhaustion. */
#define LIBSPDM_STATUS_BUFFER_FULL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x000b)

/* Cryptography errors. */

/* Generic failure originating from the cryptography module. */
#define LIBSPDM_STATUS_CRYPTO_ERROR \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CRYPTO, 0x0000)

/* Verification of the provided signature digest or signature failed. */
#define LIBSPDM_STATUS_VERIF_FAIL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CRYPTO, 0x0001)

/* Certificate parsing errors. */

/* Certificate is malformed or does not comply to x.509 standard. */
#define LIBSPDM_STATUS_INVALID_CERT \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CERT_PARSE, 0x0000)


/* Transport errors. */

/* Unable to send message to peer. */
#define LIBSPDM_STATUS_SEND_FAIL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPSM_SOURCE_TRANSPORT, 0x0000)

/* Unable to receive message from peer. */
#define LIBSPDM_STATUS_RECEIVE_FAIL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPSM_SOURCE_TRANSPORT, 0x0001)

/* Random number generation errors. */

/* Unable to produce random number due to lack of entropy. */
#define LIBSPDM_STATUS_LOW_ENTROPY \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPSM_SOURCE_RNG, 0x0000)

#endif
