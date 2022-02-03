#ifndef SPDM_RETURN_STATUS_H
#define SPDM_RETURN_STATUS_H

#include <stdint.h>

/** The layout of libspdm_return_t is
 * [31:28] - severity
 * [27:24] - reserved
 * [23:16] - source
 * [15:00] - code
 **/
typedef uint32_t libspdm_return_t;

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
    (((severity) << 28) | ((source) << 16) | (code))

/* Success status is always 0x00000000. */
#define LIBSPDM_STATUS_SUCCESS \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_SUCCESS, LIBSPDM_SOURCE_SUCCESS, 0x0000)

/* Core errors. */

/* Unable to complete operation due to unsupported capabilities by the caller. */
#define LIBSPDM_STATUS_UNSUPPORTED_CAP_LOCAL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0000)

/* Unable to complete operation due to unsupported capabilities by the peer. */
#define LIBSPDM_STATUS_UNSUPPORTED_CAP_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0001)

/* Unable to complete operation due to unsupported capabilities by both the caller and the peer. */
#define LIBSPDM_STATUS_UNSUPPORTED_CAP_BOTH \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0002)

/* Unable to complete operation due to caller's state. */
#define LIBSPDM_STATUS_INVALID_STATE_LOCAL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0003)

/* Unable to complete operation due to peer's state. */
#define LIBSPDM_STATUS_INVALID_STATE_PEER \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0004)

/* The received message contains one or more invalid message fields. */
#define LIBSPDM_STATUS_INVALID_MESS_FIELD \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x0005)

/* Cryptography errors. */

/* Verification of the provided signature failed. */
#define LIBSPDM_STATUS_SIG_VERIF_FAIL \
    LIBSPDM_STATUS_CONSTRUCT(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CRYPTO, 0x0000)


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
