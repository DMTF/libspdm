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

#ifndef TCP_BINDING_H
#define TCP_BINDING_H

#pragma pack(1)

typedef struct {
    uint16_t payload_length;
    uint8_t binding_version;
    uint8_t message_type;
} tcp_spdm_binding_header_t;

#define TCP_MESSAGE_TYPE_OUT_OF_SESSION 0x05
#define TCP_MESSAGE_TYPE_IN_SESSION 0x06
#define TCP_MESSAGE_TYPE_ROLE_INQUIRY 0xBF

/* Error Messages*/
#define TCP_MESSAGE_TYPE_ERROR_TOO_LARGE 0xC0
#define TCP_MESSGAE_TYPE_ERROR_NOT_SUPPORTED 0xC1
#define TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_REQUESTER 0xC2
#define TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_RESPONDER 0xC3

#define TCP_SEQUENCE_NUMBER_COUNT 0
#define TCP_MAX_RANDOM_NUMBER_COUNT 0

#pragma pack()

#endif /* TCP_BINDING_H */
