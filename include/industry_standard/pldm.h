/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Definitions of DSP0240 Platform Level data Model (PLDM) Base Specification
  version 1.0.0 in Distributed Management Task Force (DMTF).

  Definitions of DSP0245 Platform Level data Model (PLDM) IDs and Codes Specification
  version 1.3.0 in Distributed Management Task Force (DMTF).
**/

#ifndef __PLDM_H__
#define __PLDM_H__

#pragma pack(1)

typedef struct {
	uint8 instance_id;
	uint8 pldm_type;
	uint8 pldm_command_code;
	//uint8    payload[];
} pldm_message_header_t;

typedef struct {
	uint8 pldm_completion_code;
} pldm_message_response_header_t;

#define PLDM_BASE_CODE_SUCCESS 0
#define PLDM_BASE_CODE_ERROR 1

#define PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY 0x00
#define MCTP_MESSAGE_TYPE_SMBIOS 0x01
#define MCTP_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL 0x02
#define MCTP_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION 0x03
#define MCTP_MESSAGE_TYPE_FRU_DATA 0x04
#define MCTP_MESSAGE_TYPE_FIRMWARE_UPDATE 0x05
#define MCTP_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT 0x06
#define MCTP_MESSAGE_TYPE_OEM 0x3F

//
// PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY
//
#define PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID 0x01
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID 0x02
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION 0x03
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES 0x04
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS 0x05

#pragma pack()

#endif
