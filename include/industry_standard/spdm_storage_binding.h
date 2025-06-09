/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
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
} spdm_storage_response_header_t;

typedef struct {
    spdm_storage_response_header_t storage_response_headers;
    uint8_t conn_params;
    uint8_t reserved1[3];
    uint8_t supported_operations;
    uint8_t reserved2[7];
    uint8_t reserved3[16];
} spdm_storage_discovery_response_t;

typedef struct {
    spdm_storage_response_header_t storage_response_headers;
    uint32_t pending_info_flag;
    uint32_t response_length;
} spdm_storage_pending_info_response_t;

typedef struct {
    uint8_t rsvd1;
    uint8_t desc_type;
    uint8_t status;
    uint8_t rsvd2;
    uint32_t length;
    uint32_t offset;
    uint32_t rsvd3;
} spdm_storage_secured_message_descriptor;

typedef enum
{
    SPDM_STORAGE_SECURED_MSG_DESCRIPTOR_NVME = 0x01,
    SPDM_STORAGE_SECURED_MSG_DESCRIPTOR_SCSI = 0x02,
    SPDM_STORAGE_SECURED_MSG_DESCRIPTOR_ATA = 0x03,
    SPDM_STORAGE_SECURED_MSG_DESCRIPTOR_SPDM = 0x04,
    SPDM_STORAGE_SECURED_MSG_DESCRIPTOR_DATA_BUFFER = 0x40
} spdm_storage_secured_message_descriptor_t;

typedef enum
{
    SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_SUCCESS = 0x00,
    SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_GENERAL_ERROR = 0x01,
    SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_INVALID_CMD = 0x02,
    SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_INVALID_FIELD = 0x03,
    SPDM_STORAGE_SECURED_MSG_ENCAPSULATED_STATUS_VENDOR_DEFINED = 0xFF
} spdm_storage_secured_message_encapsulated_status_t;

#define SPDM_STORAGE_SEQUENCE_NUMBER_COUNT 2
#define SPDM_STORAGE_SECURITY_BINDING_VERSION 0x1000
#define SPDM_STORAGE_SECURITY_PROTOCOL_DMTF 0xE8

#define SPDM_STORAGE_OPERATION_CODE_DISCOVERY        0x01
#define SPDM_STORAGE_OPERATION_CODE_PENDING_INFO     0x02
#define SPDM_STORAGE_OPERATION_CODE_MESSAGE          0x05
#define SPDM_STORAGE_OPERATION_CODE_SECURED_MESSAGE  0x06

#define SPDM_STORAGE_MAX_CONNECTION_ID_MASK 0x3

#pragma pack()

#endif /* SPDM_STORAGE_BINDING_H */
