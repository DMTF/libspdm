/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of Integrity and data Encryption (IDE) in the PCIe Base specification.
 **/

#ifndef PCI_IDE_KM_H
#define PCI_IDE_KM_H

#pragma pack(1)

/* IDE_KM header */
typedef struct {
    uint8_t object_id;
} pci_ide_km_header_t;

#define PCI_IDE_KM_OBJECT_ID_QUERY 0x00
#define PCI_IDE_KM_OBJECT_ID_QUERY_RESP 0x01
#define PCI_IDE_KM_OBJECT_ID_KEY_PROG 0x02
#define PCI_IDE_KM_OBJECT_ID_KP_ACK 0x03
#define PCI_IDE_KM_OBJECT_ID_K_SET_GO 0x04
#define PCI_IDE_KM_OBJECT_ID_K_SET_STOP 0x05
#define PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK 0x06
#define PCI_IDE_KM_OBJECT_ID_GET_KEY 0x07
#define PCI_IDE_KM_OBJECT_ID_GET_KEY_ACK 0x08
#define PCI_IDE_KM_OBJECT_ID_EN_AEAD_LC 0x09
#define PCI_IDE_KM_OBJECT_ID_EN_AEAD_LC_ACK 0x0A

/* IDE_KM QUERY */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved;
    uint8_t port_index;
} pci_ide_km_query_t;

/* IDE_KM QUERY_RESP */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t caps;
    uint8_t port_index;
    uint8_t dev_func_num;
    uint8_t bus_num;
    uint8_t segment;
    uint8_t max_port_index;
    /* IDE Extended capability */
} pci_ide_km_query_resp_t;

#define PCI_IDE_KM_QUERY_RESP_CAP_VERSION_MASK 0x0F
#define PCI_IDE_KM_QUERY_RESP_CAP_VERSION_1 0x01
#define PCI_IDE_KM_QUERY_RESP_IV_GEN_CAP 0x10
#define PCI_IDE_KM_QUERY_RESP_KEY_GEN_CAP 0x20
#define PCI_IDE_KM_QUERY_RESP_AEAD_LC_CAP 0x40
#define PCI_IDE_KM_QUERY_RESP_AEAD_LC_PROG_CAP 0x80

#define PCI_IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT 8
#define PCI_IDE_KM_SELECTIVE_IDE_REG_BLOCK_MAX_COUNT 256
#define PCI_IDE_KM_SELECTIVE_IDE_ADDRESS_ASSOCIATION_REG_BLOCK_MAX_COUNT 15

/* IDE_KM KEY_PROG */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    /* KEY 8 DW
     * IFV(invocation field of the IV) 2 DW */
} pci_ide_km_key_prog_t;

#define PCI_IDE_KM_KEY_SET_MASK 0x01
#define PCI_IDE_KM_KEY_SET_K0 0x00
#define PCI_IDE_KM_KEY_SET_K1 0x01

#define PCI_IDE_KM_KEY_DIRECTION_MASK 0x02
#define PCI_IDE_KM_KEY_DIRECTION_RX 0x00
#define PCI_IDE_KM_KEY_DIRECTION_TX 0x02

#define PCI_IDE_KM_KEY_SUB_STREAM_MASK 0x70
#define PCI_IDE_KM_KEY_SUB_STREAM_PR 0x00
#define PCI_IDE_KM_KEY_SUB_STREAM_NPR 0x10
#define PCI_IDE_KM_KEY_SUB_STREAM_CPL 0x20

/* IDE_KM KP_ACK */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t status;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_kp_ack_t;

#define PCI_IDE_KM_KP_ACK_STATUS_SUCCESS 0x00
#define PCI_IDE_KM_KP_ACK_STATUS_INCORRECT_LENGTH 0x01
#define PCI_IDE_KM_KP_ACK_STATUS_UNSUPPORTED_PORT_INDEX 0x02
#define PCI_IDE_KM_KP_ACK_STATUS_UNSUPPORTED_VALUE 0x03
#define PCI_IDE_KM_KP_ACK_STATUS_UNSPECIFIED_FAILURE 0x04
#define PCI_IDE_KM_KP_ACK_STATUS_INVALID_KEY 0x05
#define PCI_IDE_KM_KP_ACK_STATUS_INVALID_IV 0x06

/* IDE_KM K_SET_GO */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_set_go_t;

/* IDE_KM K_SET_STOP */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_set_stop_t;

/* IDE_KM K_GOSTOP_ACK */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_k_gostop_ack_t;

/* IDE_KM GETKEY */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
} pci_ide_km_get_key_t;

/* IDE_KM GETKEY_ACK */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t reserved2;
    uint8_t key_sub_stream;
    uint8_t port_index;
    /* KEY 8 DW
     * IFV(invocation field of the IV) 2 DW */
} pci_ide_km_get_key_ack_t;

/* IDE_KM EN_AEAD_LC */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t aead_limit_counter_exponent;
    uint8_t reserved2;
    uint8_t port_index;
} pci_ide_km_en_aead_lc_t;

/* A value of 0 means an exponent of 64. */
#define PCI_IDE_KM_AEAD_LIMIT_COUNTER_EXPONENT_MASK 0x3F

/* IDE_KM EN_AEAD_LC_ACK */
typedef struct {
    pci_ide_km_header_t header;
    uint8_t reserved[2];
    uint8_t stream_id;
    uint8_t aead_limit_counter_exponent;
    uint8_t reserved2;
    uint8_t port_index;
} pci_ide_km_en_aead_lc_ack_t;

#pragma pack()

#endif /* PCI_IDE_KM_H */
