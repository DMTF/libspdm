/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of DSP0287 SPDM over TCP Binding Specification
 * version 1.0.0 in Distributed Management Task Force (DMTF).
 *
 **/

#ifndef SPDM_TCP_BINDING_H
#define SPDM_TCP_BINDING_H

#pragma pack(1)

typedef struct {
    uint16_t payload_length;
    uint8_t binding_version;
    uint8_t message_type;
} spdm_tcp_binding_header_t;

#define SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION 0x05
#define SPDM_TCP_MESSAGE_TYPE_IN_SESSION 0x06
#define SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY 0xBF

/* Error Messages*/
#define SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE 0xC0
#define SPDM_TCP_MESSAGE_TYPE_ERROR_NOT_SUPPORTED 0xC1
#define SPDM_TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_REQUESTER 0xC2
#define SPDM_TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_RESPONDER 0xC3
#define SPDM_TCP_MESSAGE_TYPE_ERROR_RESERVED_MIN 0xC4
#define SPDM_TCP_MESSAGE_TYPE_ERROR_RESERVED_MAX 0xFF

#define SPDM_TCP_SEQUENCE_NUMBER_COUNT 0
#define SPDM_TCP_MAX_RANDOM_NUMBER_COUNT 0

#pragma pack()

#endif /* SPDM_TCP_BINDING_H */
