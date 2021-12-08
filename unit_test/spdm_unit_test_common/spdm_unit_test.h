/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
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

extern uint8_t m_use_measurement_spec;
extern uint32_t m_use_measurement_hash_algo;
extern uint32_t m_use_hash_algo;
extern uint32_t m_use_asym_algo;
extern uint16_t m_use_req_asym_algo;
extern uint16_t m_use_dhe_algo;
extern uint16_t m_use_aead_algo;
extern uint16_t m_use_key_schedule_algo;

///
/// SPDM reserved error code
/// They are for unit test only. 
/// Please double check if they are still reserved when a new SPDM spec is published.
///
#define SPDM_ERROR_CODE_RESERVED_00             0x00
#define SPDM_ERROR_CODE_RESERVED_0D             0x0D
#define SPDM_ERROR_CODE_RESERVED_3F             0x3F
#define SPDM_ERROR_CODE_RESERVED_FD             0xFD

#define ASSERT_INT_EQUAL_CASE(value, expected, case) {\
      if(value != expected) {\
        fprintf(stderr, "[ERRCODE:%02x] ", case);\
      } \
      assert_int_equal(value, expected);\
    };

#define SPDM_TEST_CONTEXT_SIGNATURE SIGNATURE_32('S', 'T', 'C', 'S')

typedef struct {
    uint32_t signature;
    boolean is_requester;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    void *spdm_context;
    uint32_t case_id;
} spdm_test_context_t;

#define SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(a)                                \
    BASE_CR(a, spdm_test_context_t, SpdmProtocol)
#define SPDM_TEST_CONTEXT_FROM_SPDM_CONTEXT(a)                                 \
    BASE_CR(a, spdm_test_context_t, spdm_context)

int spdm_unit_test_group_setup(void **state);

int spdm_unit_test_group_teardown(void **state);

void setup_spdm_test_context(IN spdm_test_context_t *spdm_test_context);

spdm_test_context_t *get_spdm_test_context(void);

void dump_hex_str(IN uint8_t *buffer, IN uintn buffer_size);

void dump_data(IN uint8_t *buffer, IN uintn buffer_size);

void dump_hex(IN uint8_t *buffer, IN uintn buffer_size);

boolean read_input_file(IN char8 *file_name, OUT void **file_data,
            OUT uintn *file_size);

#endif
