/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_UNIT_TEST_H__
#define __SPDM_UNIT_TEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#undef NULL
#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_test_lib.h"
#include "internal/libspdm_common_lib.h"
#include "spdm_device_secret_lib_internal.h"

extern uint8_t m_libspdm_use_measurement_spec;
extern uint32_t m_libspdm_use_measurement_hash_algo;
extern uint32_t m_libspdm_use_hash_algo;
extern uint32_t m_libspdm_use_asym_algo;
extern uint16_t m_libspdm_use_req_asym_algo;
extern uint16_t m_libspdm_use_dhe_algo;
extern uint16_t m_libspdm_use_aead_algo;
extern uint16_t m_libspdm_use_key_schedule_algo;
extern uint8_t m_libspdm_use_tcb_hash_value[LIBSPDM_MAX_HASH_SIZE];


/* SPDM reserved error code
 * They are for unit test only.
 * Please double check if they are still reserved when a new SPDM spec is published.*/

#define LIBSPDM_ERROR_CODE_RESERVED_00             0x00
#define LIBSPDM_ERROR_CODE_RESERVED_0D             0x0D
#define LIBSPDM_ERROR_CODE_RESERVED_3F             0x3F
#define LIBSPDM_ERROR_CODE_RESERVED_FD             0xFD

#define LIBSPDM_ASSERT_INT_EQUAL_CASE(value, expected, case) { \
        if(value != expected) { \
            fprintf(stderr, "[ERRCODE:%02x] ", case); \
        } \
        assert_int_equal(value, expected); \
};

#define LIBSPDM_TEST_CONTEXT_SIGNATURE SIGNATURE_32('S', 'T', 'C', 'S')

typedef struct {
    uint32_t signature;
    bool is_requester;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    void *spdm_context;
    void *scratch_buffer;
    uintn scratch_buffer_size;
    uint32_t case_id;
} libspdm_test_context_t;

int libspdm_unit_test_group_setup(void **state);

int libspdm_unit_test_group_teardown(void **state);

void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context);

libspdm_test_context_t *libspdm_get_test_context(void);

void libspdm_dump_hex_str(const uint8_t *buffer, uintn buffer_size);

void libspdm_dump_data(const uint8_t *buffer, uintn buffer_size);

void libspdm_dump_hex(const uint8_t *buffer, uintn buffer_size);

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             uintn *file_size);

#endif
