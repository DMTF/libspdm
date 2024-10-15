/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions in CXL 3.1 specification.
 **/

#ifndef CXL_TSP_H
#define CXL_TSP_H

#define CXL_PROTOCOL_ID_TSP 0x01

#pragma pack(1)

/* TSP header*/

#define CXL_TSP_MESSAGE_VERSION_10 0x10
#define CXL_TSP_MESSAGE_VERSION CXL_TSP_MESSAGE_VERSION_10

typedef struct {
    uint8_t tsp_version;
    uint8_t op_code;
} cxl_tsp_header_t;

#define CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION 0x81
#define CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES 0x82
#define CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION 0x83
#define CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION 0x84
#define CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT 0x85
#define CXL_TSP_OPCODE_LOCK_TARGET_CONFIGURATION 0x86
#define CXL_TSP_OPCODE_SET_TARGET_CKID_SPECIFIC_KEY 0x87
#define CXL_TSP_OPCODE_SET_TARGET_CKID_RANDOM_KEY 0x88
#define CXL_TSP_OPCODE_CLEAR_TARGET_CKID_KEY 0x89
#define CXL_TSP_OPCODE_SET_TARGET_RANGE_SPECIFIC_KEY 0x8A
#define CXL_TSP_OPCODE_SET_TARGET_RANGE_RANDOM_KEY 0x8B
#define CXL_TSP_OPCODE_CLEAR_TARGET_RANGE_KEY 0x8C
#define CXL_TSP_OPCODE_SET_TARGET_TE_STATE 0x8D
#define CXL_TSP_OPCODE_CHECK_TARGET_DELAYED_COMPLETION 0x8E

#define CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION_RSP 0x01
#define CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES_RSP 0x02
#define CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION_RSP 0x03
#define CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_RSP 0x04
#define CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT_RSP 0x05
#define CXL_TSP_OPCODE_LOCK_TARGET_CONFIGURATION_RSP 0x06
#define CXL_TSP_OPCODE_SET_TARGET_CKID_SPECIFIC_KEY_RSP 0x07
#define CXL_TSP_OPCODE_SET_TARGET_CKID_RANDOM_KEY_RSP 0x08
#define CXL_TSP_OPCODE_CLEAR_TARGET_CKID_KEY_RSP 0x09
#define CXL_TSP_OPCODE_SET_TARGET_RANGE_SPECIFIC_KEY_RSP 0x0A
#define CXL_TSP_OPCODE_SET_TARGET_RANGE_RANDOM_KEY_RSP 0x0B
#define CXL_TSP_OPCODE_CLEAR_TARGET_RANGE_KEY_RSP 0x0C
#define CXL_TSP_OPCODE_SET_TARGET_TE_STATE_RSP 0x0D
#define CXL_TSP_OPCODE_CHECK_TARGET_DELAYED_COMPLETION_RSP 0x0E
#define CXL_TSP_OPCODE_DELAYED_RSP 0x7E
#define CXL_TSP_OPCODE_ERROR_RSP 0x7F

/* Get Target TSP Version */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_get_target_tsp_version_req_t;

/* Get Target TSP Version Response */

typedef uint8_t cxl_tsp_version_number_t;

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint8_t version_number_entry_count;
    /*cxl_tsp_version_number_t version_number_entry[version_number_entry_count];*/
} cxl_tsp_get_target_tsp_version_rsp_t;

/* Get Target Capabilities */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_get_target_capabilities_req_t;

/* Get Target Capabilities Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t memory_encryption_features_supported;
    uint32_t memory_encryption_algorithms_supported;
    uint16_t memory_encryption_number_of_range_based_keys;
    uint16_t reserved;
    uint16_t te_state_change_and_access_control_features_supported;
    uint16_t reserved2;
    uint32_t supported_explicit_oob_te_state_granularity;
    uint32_t supported_explicit_ib_te_state_granularity;
    uint16_t configuration_features_supported;
    uint16_t reserved3;
    uint32_t number_of_ckids;
    uint8_t number_of_secondary_sessions;
    uint8_t reserved4[0x13];
} cxl_tsp_get_target_capabilities_rsp_t;

#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_ENCRYPTION 0x1
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_ENCRYPTION 0x2
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_RANGE_BASED_ENCRYPTION 0x4
/* only valid in CAP, not in SET/GET */
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_INITIATOR_SUPPLIED_ENTROPY 0x8
/* offset is changed in SET/GET */
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_SUPPORT_CKID_BASED_REQUIRED 0x10

#define CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_128 0x1
#define CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_AES_XTS_256 0x2
#define CXL_TSP_MEMORY_ENCRYPTION_ALGORITHMS_VENDOR_SPECIFIC 0x80000000

#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_WRITE_ACCESS_CONTROL 0x1
#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_READ_ACCESS_CONTROL 0x2
#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_IMPLICIT_TE_STATE_CHANGE 0x4
#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_OOB_TE_STATE_CHANGE 0x8
#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_IB_TE_STATE_CHANGE 0x10
#define CXL_TSP_TE_STATE_CHANGE_AND_ACCESS_CONTROL_FEATURES_EXPLICIT_TE_STATE_CHANGE_SANITIZE 0x20

#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_64B 0x1
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_128B 0x2
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_256B 0x4
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_512B 0x8
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_1K 0x10
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_2K 0x20
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_4K 0x40
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_8K 0x80
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_16K 0x100
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_32K 0x200
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_64K 0x400
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_128K 0x800
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_256K 0x1000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_512K 0x2000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_1MB 0x4000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_2MB 0x8000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_4MB 0x10000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_8MB 0x20000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_16MB 0x40000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_32MB 0x80000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_64MB 0x100000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_128MB 0x200000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_256MB 0x400000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_512MB 0x800000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_1GB 0x1000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_2GB 0x2000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_4GB 0x4000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_8GB 0x8000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_16GB 0x10000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_32GB 0x20000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_64GB 0x40000000
#define CXL_TSP_EXPLICIT_OOB_TE_STATE_CHANGE_GRANULARITY_128GB 0x80000000

#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_64B 0x1
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_128B 0x2
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_256B 0x4
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_512B 0x8
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_1K 0x10
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_2K 0x20
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_4K 0x40
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_8K 0x80
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_16K 0x100
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_32K 0x200
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_64K 0x400
#define CXL_TSP_EXPLICIT_IB_TE_STATE_CHANGE_GRANULARITY_ENTIRE_MEMORY 0x80000000

#define CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_LOCKED_TARGET_FW_UPDATE 0x1
/* only valid in CAP, not in SET/GET */
#define CXL_TSP_CONFIGURATION_FEATURES_SUPPORT_TARGET_SUPPORT_ADDITIONAL_SPDM_SESSIONS 0x2

/* Set Target Configuration */

#define CXL_TSP_2ND_SESSION_COUNT 4
#define CXL_TSP_2ND_SESSION_KEY_SIZE 0x20

typedef struct {
    uint64_t te_state_granularity;
    uint8_t length_index;
    uint8_t reserved[7];
} cxl_tsp_explicit_ib_te_state_granularity_entry_t;

typedef struct {
    uint8_t key_material[CXL_TSP_2ND_SESSION_KEY_SIZE];
} cxl_tsp_secondary_session_psk_key_material_t;

typedef struct {
    cxl_tsp_header_t header;
    uint16_t memory_encryption_features_enable;
    uint32_t memory_encryption_algorithm_select;
    uint32_t reserved;
    uint16_t te_state_change_and_access_control_features_enable;
    uint16_t reserved2;
    uint32_t explicit_oob_te_state_granularity;
    uint32_t reserved3;
    uint16_t configuration_features_enable;
    uint16_t reserved4;
    uint32_t ckid_base;
    uint32_t number_of_ckids;
    uint8_t reserved5[0xc];
    cxl_tsp_explicit_ib_te_state_granularity_entry_t
        explicit_ib_te_state_granularity_entry[8];
    uint8_t reserved6[0x10];
    uint16_t configuration_validity_flags;
    uint8_t reserved7[0xe];
    uint8_t secondary_session_ckid_type;
    uint8_t reserved8[0xf];
    cxl_tsp_secondary_session_psk_key_material_t
        secondary_session_psk_key_material[CXL_TSP_2ND_SESSION_COUNT];
} cxl_tsp_set_target_configuration_req_t;

#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_ENCRYPTION 0x1
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_ENCRYPTION 0x2
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_RANGE_BASED_ENCRYPTION 0x4
#define CXL_TSP_MEMORY_ENCRYPTION_FEATURES_ENABLE_CKID_BASED_REQUIRED 0x8

#define CXL_TSP_CONFIGURATION_FEATURES_ENABLE_LOCKED_TARGET_FW_UPDATE 0x1
/* only valid in SET, not in GET */
#define CXL_TSP_CONFIGURATION_FEATURES_ENABLE_SPECIAL_PURPOSE_MEMORY 0x2

#define CXL_TSP_2ND_SESSION_0_PSK_HINT_STRING "SECONDARY_SESSION_0_PSK"
#define CXL_TSP_2ND_SESSION_1_PSK_HINT_STRING "SECONDARY_SESSION_1_PSK"
#define CXL_TSP_2ND_SESSION_2_PSK_HINT_STRING "SECONDARY_SESSION_2_PSK"
#define CXL_TSP_2ND_SESSION_3_PSK_HINT_STRING "SECONDARY_SESSION_3_PSK"

/* Set Target Configuration Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_configuration_rsp_t;

/* Get Target Configuration */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_get_target_configuration_req_t;

/* Get Target Configuration Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t memory_encryption_features_enabled;
    uint32_t memory_encryption_algorithm_selected;
    uint32_t reserved;
    uint16_t te_state_change_and_access_control_features_enabled;
    uint16_t reserved2;
    uint32_t explicit_oob_te_state_granularity_enabled;
    uint32_t reserved3;
    uint16_t configuration_features_enabled;
    uint16_t reserved4;
    uint32_t ckid_base;
    uint32_t number_of_ckids;
    uint8_t current_tsp_state;
    uint8_t reserved5[0xb];
    cxl_tsp_explicit_ib_te_state_granularity_entry_t
        explicit_ib_te_state_granularity_entry[8];
    uint8_t reserved6[0x10];
} cxl_tsp_get_target_configuration_rsp_t;

#define CXL_TSP_STATE_CONFIG_UNLOCKED 0
#define CXL_TSP_STATE_CONFIG_LOCKED 1
#define CXL_TSP_STATE_ERROR 2

/* Get Target Configuration Report */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint16_t offset;
    uint16_t length;
} cxl_tsp_get_target_configuration_report_req_t;

/* Get Target Configuration Report Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint16_t portion_length;
    uint16_t remainder_length;
    /* uint8_t report_data[portion_length]; */
} cxl_tsp_get_target_configuration_report_rsp_t;

typedef struct {
    uint8_t valid_tsp_report_fields;
    uint8_t reserved[3];
    /* uint8_t pcie_dvsec_for_cxl_devices[0x3c];
     * uint8_t pcie_dvsec_for_flex_bus_port[0x20];
     * uint8_t cxl_link_capability_structure[0x38];
     * uint8_t cxl_timeout_and_isolation_capability_structure[0x10];
     * uint8_t cxl_hdm_decoder_capability_structure[0x10];
     * uint8_t cxl_hdm_decoder[decoder_count];
     * uint8_t cxl_ide_capability_structure[0x24]; */
} cxl_tsp_target_configuration_report_t;

/* Lock Target Configuration */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_lock_target_configuration_req_t;

/* Lock Target Configuration Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_lock_target_configuration_rsp_t;

/* Set Target TE State */

typedef struct {
    cxl_tsp_header_t header;
    uint8_t te_state;
    uint8_t number_of_memory_ranges;
    uint8_t reserved[0xc];
    /* cxl_tsp_memory_range_t memory_ranges[number_of_memory_ranges] */
} cxl_tsp_set_target_te_state_req_t;

typedef struct {
    uint64_t starting_address;
    uint64_t length;
} cxl_tsp_memory_range_t;

/* Set Target TE State Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_te_state_rsp_t;

/* Set Target CKID Specific Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t ckid;
    uint8_t ckid_type;
    uint8_t reserved2[6];
    uint8_t validity_flags;
    uint8_t data_encryption_key[0x20];
    uint8_t tweak_key[0x20];
} cxl_tsp_set_target_ckid_specific_key_req_t;

#define CXL_TSP_SET_CKID_SPECIFIC_KEY_CKID_TYPE_TVM_CKID 1
#define CXL_TSP_SET_CKID_SPECIFIC_KEY_CKID_TYPE_OS_CKID 2

#define CXL_TSP_KEY_VALIDITY_FLAGS_DATA_ENC_KEY 0x1
#define CXL_TSP_KEY_VALIDITY_FLAGS_TWEAK_KEY 0x2

/* Set Target CKID Specific Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_ckid_specific_key_rsp_t;

/* Set Target CKID Random Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t ckid;
    uint8_t attributes;
    uint8_t reserved2[6];
    uint8_t validity_flags;
    uint8_t data_encryption_key[0x20];
    uint8_t tweak_key[0x20];
} cxl_tsp_set_target_ckid_random_key_req_t;

#define CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_MASK 0x1
#define CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_TVM_CKID 0x1
#define CXL_TSP_SET_CKID_RANDOM_KEY_ATTRIBUTES_CKID_TYPE_OS_CKID 0x0

/* Set Target CKID Random Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_ckid_random_key_rsp_t;

/* Clear Target CKID Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t ckid;
} cxl_tsp_clear_target_ckid_key_req_t;

/* Clear Target CKID Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_clear_target_ckid_key_rsp_t;

/* Set Target Range Specific Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t range_id;
    uint64_t range_start;
    uint64_t range_end;
    uint8_t reserved2[7];
    uint8_t validity_flags;
    uint8_t data_encryption_key[0x20];
    uint8_t tweak_key[0x20];
} cxl_tsp_set_target_range_specific_key_req_t;

/* Set Target Range Specific Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_range_specific_key_rsp_t;

/* Set Target Range Random Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t range_id;
    uint64_t range_start;
    uint64_t range_end;
    uint8_t reserved2[7];
    uint8_t validity_flags;
    uint8_t data_encryption_key[0x20];
    uint8_t tweak_key[0x20];
} cxl_tsp_set_target_range_random_key_req_t;

/* Set Target Range Random Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_set_target_range_random_key_rsp_t;

/* Clear Target Range Key */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t range_id;
} cxl_tsp_clear_target_range_key_req_t;

/* Clear Target Range Key Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_clear_target_range_key_rsp_t;

/* Delayed Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t delay_time;
} cxl_tsp_delayed_rsp_t;

/* Check Target Delayed Completion */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_check_delayed_completion_req_t;

/* Check Target Delayed Completion Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
} cxl_tsp_check_delayed_completion_rsp_t;

/* Error Response */

typedef struct {
    cxl_tsp_header_t header;
    uint16_t reserved;
    uint32_t error_code;
    uint32_t error_data;
    /* uint8_t extended_error_data[] */
} cxl_tsp_error_rsp_t;

/* TSP error code */

#define CXL_TSP_ERROR_CODE_INVALID_REQUEST 0x01
#define CXL_TSP_ERROR_CODE_BUSY 0x02
#define CXL_TSP_ERROR_CODE_UNSPECIFIED 0x03
#define CXL_TSP_ERROR_CODE_UNSUPPORTED_REQUEST 0x04
#define CXL_TSP_ERROR_CODE_VERSION_MISMATCH 0x05
#define CXL_TSP_ERROR_CODE_VENDOR_SPECIFIC_ERROR 0x06
#define CXL_TSP_ERROR_CODE_NO_PRIVILEGE 0x07
#define CXL_TSP_ERROR_CODE_NO_ENTROPY 0x08
#define CXL_TSP_ERROR_CODE_INVALID_CKID 0x09
#define CXL_TSP_ERROR_CODE_INVALID_SECURITY_CONFIGURATION 0x0A
#define CXL_TSP_ERROR_CODE_INVALID_SECURITY_STATE 0x0B
#define CXL_TSP_ERROR_CODE_LONG_EXECUTION_TIME 0x0C
#define CXL_TSP_ERROR_CODE_ALREADY_LOCKED 0x0D

#pragma pack()

#endif /* CXL_TSP_H */
