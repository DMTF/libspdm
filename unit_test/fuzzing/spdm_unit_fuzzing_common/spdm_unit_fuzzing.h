/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_UNIT_FUZZING_H__
#define __SPDM_UNIT_FUZZING_H__

#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_transport_test_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"

extern uint8_t m_libspdm_use_measurement_spec;
extern uint32_t m_libspdm_use_measurement_hash_algo;
extern uint32_t m_libspdm_use_hash_algo;
extern uint32_t m_libspdm_use_asym_algo;
extern uint16_t m_libspdm_use_req_asym_algo;
extern uint16_t m_libspdm_use_dhe_algo;
extern uint16_t m_libspdm_use_aead_algo;
extern uint16_t m_libspdm_use_key_schedule_algo;

#define LIBSPDM_TEST_CONTEXT_VERSION 0x1

typedef struct {
    uint32_t version;
    bool is_requester;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    void *spdm_context;
    void *scratch_buffer;
    size_t scratch_buffer_size;
    const void *test_buffer;
    size_t test_buffer_size;
} libspdm_test_context_t;

size_t libspdm_unit_test_group_setup(void **State);

size_t libspdm_unit_test_group_teardown(void **State);

void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context);

libspdm_test_context_t *libspdm_get_test_context(void);

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

void libspdm_dump_data(const uint8_t *buffer, size_t buffer_size);

void libspdm_dump_hex(const uint8_t *buffer, size_t buffer_size);

#endif
