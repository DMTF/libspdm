/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Definitions of Component Measurement and Authentication (CMA) ECN in PCI-SIG.

  Definitions of data Object Exchange (DOE) ECN in PCI-SIG.

  Definitions of Integrity and data Encryption (IDE) ECN in PCI-SIG.
**/

#ifndef __PCI_DOE_BINDING_H__
#define __PCI_DOE_BINDING_H__

#pragma pack(1)

//
// DOE header
//
typedef struct {
	uint16 vendor_id;
	uint8 data_object_type;
	uint8 reserved;
	// length of the data object being transfered in number of DW, including the header (2 DW)
	// It only includes bit[0~17], bit[18~31] are reserved.
	// A value of 00000h indicate 2^18 DW == 2^20 byte.
	uint32 length;
	//uint32   data_object_dw[length];
} pci_doe_data_object_header_t;

#define PCI_DOE_VENDOR_ID_PCISIG 0x0001

#define PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY 0x00
#define PCI_DOE_DATA_OBJECT_TYPE_SPDM 0x01
#define PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM 0x02

#define PCI_DOE_MAX_SIZE_IN_BYTE 0x00100000
#define PCI_DOE_MAX_SIZE_IN_DW 0x00040000

//
// DOE Discovery
//
typedef struct {
	uint8 index;
	uint8 reserved[3];
} pci_doe_discovery_request_t;

typedef struct {
	uint16 vendor_id;
	uint8 data_object_type;
	uint8 next_index;
} pci_doe_discovery_response_t;

#pragma pack()

#endif
