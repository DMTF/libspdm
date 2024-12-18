/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of SPDM over the Storage as defined in DSP0286
 **/

#ifndef SPDM_STORAGE_BINDING_H
#define SPDM_STORAGE_BINDING_H

#pragma pack(1)

typedef struct {
    uint16_t data_length;
    uint16_t storage_binding_version;
    uint8_t connection_parameters;
    uint8_t reserved1[3];
    uint8_t supported_operations;
    uint8_t reserved2[7];
    uint8_t reserved3[16];
} spdm_storage_discovery_response_t;

typedef struct {
    uint16_t data_length;
    uint16_t storage_binding_version;
    uint32_t pending_info_flag;
    uint32_t response_length;
} spdm_storage_pending_info_response_t;

#define SPDM_STORAGE_SECURITY_BINDING_VERSION 0x1000
#define SPDM_STORAGE_SECURITY_PROTOCOL_DMTF 0xE8

#define SPDM_STORAGE_OPERATION_CODE_DISCOVERY        0x01
#define SPDM_STORAGE_OPERATION_CODE_PENDING_INFO     0x02
#define SPDM_STORAGE_OPERATION_CODE_MESSAGE          0x05
#define SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE  0x06

#define SPDM_STORAGE_MAX_CONNECTION_ID_MASK 0x3

#pragma pack()

#endif /* STORAGE_BINDING_H */
