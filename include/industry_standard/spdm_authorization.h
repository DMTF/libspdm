/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Definitions of DSP0289 SPDM Authorization Specification
 **/

#ifndef SPDM_AUTHORIZATION_H
#define SPDM_AUTHORIZATION_H

#pragma pack(1)

#define SPDM_SPEC_ID_0289 289

#define SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_INVOKE_SEAP 0x0
#define SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_SEAP_SUCCESS 0x1
#define SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_AUTH_HELLO 0x2
#define SPDM_AUTHORIZATION_DATA_STRUCTURE_ID_MAX 0x2

typedef struct {
    uint8_t id; /* SPDM_REGISTRY_ID_DMTF_DSP */
    uint8_t vendor_len;
    uint16_t dmtf_spec_id; /* SPDM_SPEC_ID_0289 */
    uint16_t opaque_element_data_len;
    /* uint8_t aods_id;
     * uint8_t aods_body[]; */
} aods_general_opaque_data_table_header_t;

typedef struct {
    uint8_t aods_id;
} aods_general_opaque_element_header_t;

typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
    uint16_t credetial_id;
} aods_general_opaque_element_invoke_seap_t;

typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
} aods_general_opaque_element_seap_success_t;

typedef struct {
    uint8_t aods_id;
    uint8_t presence_extension;
} aods_general_opaque_element_auth_hello_t;

#pragma pack()

#endif /* SPDM_AUTHORIZATION_H */
