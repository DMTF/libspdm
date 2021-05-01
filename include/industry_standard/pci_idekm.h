/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Definitions of Integrity and data Encryption (IDE) ECN in PCI-SIG.
**/

#ifndef __PCI_IDE_KM_H__
#define __PCI_IDE_KM_H__

//
// Standard ID and Vendor ID for PCISIG
//
#define SPDM_STANDARD_ID_PCISIG SPDM_REGISTRY_ID_PCISIG
#define SPDM_VENDOR_ID_PCISIG 0x0001

#pragma pack(1)

//
// PCI Protocol definition
//
typedef struct {
	uint8 protocol_id;
} pci_protocol_header_t;

//
// IDE_KM Definition
//
#define PCI_PROTOCAL_ID_IDE_KM 0x00

//
// IDE_KM header
//
typedef struct {
	uint8 object_id;
} pci_ide_km_header_t;

#define PCI_IDE_KM_OBJECT_ID_QUERY 0x00
#define PCI_IDE_KM_OBJECT_ID_QUERY_RESP 0x01
#define PCI_IDE_KM_OBJECT_ID_KEY_PROG 0x02
#define PCI_IDE_KM_OBJECT_ID_KP_ACK 0x03
#define PCI_IDE_KM_OBJECT_ID_K_SET_GO 0x04
#define PCI_IDE_KM_OBJECT_ID_K_SET_STOP 0x05
#define PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK 0x06

//
// IDE_KM QUERY
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved;
	uint8 port_index;
} pci_ide_km_query_t;

//
// IDE_KM QUERY_RESP
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved;
	uint8 port_index;
	uint8 dev_func_num;
	uint8 bus_num;
	uint8 segment;
	uint8 max_port_index;
	//IDE Extended capability
} pci_ide_km_query_resp_t;

//
// IDE_KM KEY_PROG
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved[2];
	uint8 stream_id;
	uint8 reserved2;
	uint8 key_sub_stream;
	uint8 port_index;
	//KEY 8 DW
	//IFV(invocation field of the IV) 2 DW
} pci_ide_km_key_prog_t;

//
// IDE_KM KP_ACK
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved[2];
	uint8 stream_id;
	uint8 reserved2;
	uint8 key_sub_stream;
	uint8 port_index;
} pci_ide_km_kp_ack_t;

//
// IDE_KM K_SET_GO
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved[2];
	uint8 stream_id;
	uint8 reserved2;
	uint8 key_sub_stream;
	uint8 port_index;
} pci_ide_km_k_set_go_t;

//
// IDE_KM K_SET_STOP
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved[2];
	uint8 stream_id;
	uint8 reserved2;
	uint8 key_sub_stream;
	uint8 port_index;
} pci_ide_km_k_set_stop_t;

//
// IDE_KM K_GOSTOP_ACK
//
typedef struct {
	pci_ide_km_header_t header;
	uint8 reserved[2];
	uint8 stream_id;
	uint8 reserved2;
	uint8 key_sub_stream;
	uint8 port_index;
} pci_ide_km_k_gostop_ack_t;

#pragma pack()

#endif
