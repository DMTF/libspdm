cmake_minimum_required(VERSION 3.5)

# Default values for backward compatibility (2 slots)
set(LIBSPDM_TPM_REQUESTER_HANDLES "0x81000011;0x81000011" CACHE STRING "Semicolon-separated list of TPM Requester Handle Strings")
set(LIBSPDM_TPM_REQUESTER_CERTCHAINS "0x1500011;0x1500011" CACHE STRING "Semicolon-separated list of TPM Requester Certificate Chain NV Indices")
set(LIBSPDM_TPM_RESPONDER_HANDLES "0x81000021;0x81000021" CACHE STRING "Semicolon-separated list of TPM Responder Handle Strings")
set(LIBSPDM_TPM_RESPONDER_CERTCHAINS "0x1500021;0x1500021" CACHE STRING "Semicolon-separated list of TPM Responder Certificate Chain NV Indices")

# Count the number of slots (variables are already CMake lists)
list(LENGTH LIBSPDM_TPM_REQUESTER_HANDLES REQUESTER_SLOT_COUNT)
list(LENGTH LIBSPDM_TPM_REQUESTER_CERTCHAINS REQUESTER_CERTCHAIN_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_HANDLES RESPONDER_SLOT_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_CERTCHAINS RESPONDER_CERTCHAIN_COUNT)

# Validate that handles and certchains have matching counts
if(NOT REQUESTER_SLOT_COUNT EQUAL REQUESTER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_HANDLES and LIBSPDM_TPM_REQUESTER_CERTCHAINS must have the same number of entries")
endif()

if(NOT RESPONDER_SLOT_COUNT EQUAL RESPONDER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_HANDLES and LIBSPDM_TPM_RESPONDER_CERTCHAINS must have the same number of entries")
endif()

message(STATUS "TPM Configuration:")
message(STATUS "  Requester slots: ${REQUESTER_SLOT_COUNT}")
message(STATUS "  Responder slots: ${RESPONDER_SLOT_COUNT}")

# Generate keys.h content dynamically
set(KEYS_H_CONTENT "/**\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright Notice:\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright 2024-2025 DMTF. All rights reserved.\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} **/\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#pragma once\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* Auto-generated TPM handle configuration */\n\n")

# Add slot count macros
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_REQUESTER_SLOT_COUNT ${REQUESTER_SLOT_COUNT}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_RESPONDER_SLOT_COUNT ${RESPONDER_SLOT_COUNT}\n\n")

# Generate requester handle definitions
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* TPM Requester Handles */\n")
math(EXPR REQUESTER_MAX_INDEX "${REQUESTER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${REQUESTER_MAX_INDEX})
    list(GET LIBSPDM_TPM_REQUESTER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_REQUESTER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_${INDEX} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_${INDEX} ${CERTCHAIN}\n")
endforeach()

set(KEYS_H_CONTENT "${KEYS_H_CONTENT}\n/* TPM Responder Handles */\n")
math(EXPR RESPONDER_MAX_INDEX "${RESPONDER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${RESPONDER_MAX_INDEX})
    list(GET LIBSPDM_TPM_RESPONDER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_RESPONDER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_${INDEX} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_${INDEX} ${CERTCHAIN}\n")
endforeach()

# Write the generated keys.h file
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/keys.h "${KEYS_H_CONTENT}")

add_library(spdm_device_secret_lib_tpm STATIC "")

target_include_directories(spdm_device_secret_lib_tpm
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_device_secret_lib_tpm
    PRIVATE
         ../spdm_device_secret_lib_sample/chal.c
        csr.c
        ../spdm_device_secret_lib_sample/endpointinfo.c
        ../spdm_device_secret_lib_sample/event.c
        ../spdm_device_secret_lib_sample/key_ex.c
        ../spdm_device_secret_lib_sample/key_pair.c
        meas.c
        lib.c
        ../spdm_device_secret_lib_sample/psk.c
        read_pub_cert.c
        read_pub_cert_pqc.c
        ../spdm_device_secret_lib_sample/read_special_cert.c
        ../spdm_device_secret_lib_sample/set_cert.c
        sign.c
        ${CMAKE_CURRENT_BINARY_DIR}/keys.h
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_device_secret_lib_tpm PRIVATE -DLIBSPDM_CPU_ARM)
endif()
