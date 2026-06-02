cmake_minimum_required(VERSION 3.5)

function(libspdm_make_contiguous_slot_ids COUNT OUT_SLOT_IDS)
    set(SLOT_IDS "")

    if(COUNT GREATER 0)
        math(EXPR MAX_INDEX "${COUNT} - 1")
        foreach(INDEX RANGE ${MAX_INDEX})
            list(APPEND SLOT_IDS ${INDEX})
        endforeach()
    endif()

    set(${OUT_SLOT_IDS} "${SLOT_IDS}" PARENT_SCOPE)
endfunction()

function(libspdm_validate_tpm_slot_ids PREFIX SLOT_IDS OUT_MASK)
    set(SLOTS_SEEN "")
    set(SLOT_MASK_EXPR "")
    set(HAS_SLOT_0 FALSE)

    foreach(SLOT_ID ${SLOT_IDS})
        if(SLOT_ID LESS 0 OR SLOT_ID GREATER 7)
            message(FATAL_ERROR "${PREFIX} slot id ${SLOT_ID} is invalid. Valid SPDM slot IDs are 0..7")
        endif()

        if(";${SLOTS_SEEN};" MATCHES ";${SLOT_ID};")
            message(FATAL_ERROR "${PREFIX} slot id ${SLOT_ID} is duplicated")
        endif()

        if(SLOT_ID EQUAL 0)
            set(HAS_SLOT_0 TRUE)
        endif()

        set(SLOTS_SEEN "${SLOTS_SEEN};${SLOT_ID}")
        if(SLOT_MASK_EXPR STREQUAL "")
            set(SLOT_MASK_EXPR "(1u << ${SLOT_ID})")
        else()
            set(SLOT_MASK_EXPR "${SLOT_MASK_EXPR} | (1u << ${SLOT_ID})")
        endif()
    endforeach()

    if(NOT HAS_SLOT_0)
        message(FATAL_ERROR "${PREFIX} slot ids must include slot 0 because the TPM sample uses slot 0 as the default certificate/signing slot")
    endif()

    set(${OUT_MASK} "(${SLOT_MASK_EXPR})" PARENT_SCOPE)
endfunction()

# Default values for the libspdm TPM sample. The responder sample uses
# non-contiguous SPDM slots 0, 1 and 4, so slot ids are configured separately
# from the handle/certchain values.
set(LIBSPDM_TPM_REQUESTER_HANDLES "0x81000011;0x81000011" CACHE STRING "Semicolon-separated list of TPM Requester Handle Strings")
set(LIBSPDM_TPM_REQUESTER_CERTCHAINS "0x1500011;0x1500011" CACHE STRING "Semicolon-separated list of TPM Requester Certificate Chain NV Indices")
set(LIBSPDM_TPM_RESPONDER_HANDLES "0x81000021;0x81000021;0x81000021" CACHE STRING "Semicolon-separated list of TPM Responder Handle Strings")
set(LIBSPDM_TPM_RESPONDER_CERTCHAINS "0x1500021;0x1500021;0x1500021" CACHE STRING "Semicolon-separated list of TPM Responder Certificate Chain NV Indices")

# Count the number of configured entries (variables are already CMake lists)
list(LENGTH LIBSPDM_TPM_REQUESTER_HANDLES REQUESTER_HANDLE_COUNT)
list(LENGTH LIBSPDM_TPM_REQUESTER_CERTCHAINS REQUESTER_CERTCHAIN_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_HANDLES RESPONDER_HANDLE_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_CERTCHAINS RESPONDER_CERTCHAIN_COUNT)

if(NOT DEFINED LIBSPDM_TPM_REQUESTER_SLOT_IDS)
    libspdm_make_contiguous_slot_ids(${REQUESTER_HANDLE_COUNT} LIBSPDM_TPM_REQUESTER_SLOT_IDS)
endif()

if(NOT DEFINED LIBSPDM_TPM_RESPONDER_SLOT_IDS)
    if(RESPONDER_HANDLE_COUNT EQUAL 3)
        set(LIBSPDM_TPM_RESPONDER_SLOT_IDS "0;1;4")
    else()
        libspdm_make_contiguous_slot_ids(${RESPONDER_HANDLE_COUNT} LIBSPDM_TPM_RESPONDER_SLOT_IDS)
    endif()
endif()

set(LIBSPDM_TPM_REQUESTER_SLOT_IDS "${LIBSPDM_TPM_REQUESTER_SLOT_IDS}" CACHE STRING "Semicolon-separated list of TPM Requester SPDM slot IDs")
set(LIBSPDM_TPM_RESPONDER_SLOT_IDS "${LIBSPDM_TPM_RESPONDER_SLOT_IDS}" CACHE STRING "Semicolon-separated list of TPM Responder SPDM slot IDs")

list(LENGTH LIBSPDM_TPM_REQUESTER_SLOT_IDS REQUESTER_SLOT_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_SLOT_IDS RESPONDER_SLOT_COUNT)

if(REQUESTER_SLOT_COUNT EQUAL 0)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS must contain at least slot 0")
endif()

if(RESPONDER_SLOT_COUNT EQUAL 0)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS must contain at least slot 0")
endif()

# Validate that slot ids, handles and certchains have matching counts
if(NOT REQUESTER_SLOT_COUNT EQUAL REQUESTER_HANDLE_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS and LIBSPDM_TPM_REQUESTER_HANDLES must have the same number of entries")
endif()

if(NOT REQUESTER_SLOT_COUNT EQUAL REQUESTER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS and LIBSPDM_TPM_REQUESTER_CERTCHAINS must have the same number of entries")
endif()

if(NOT RESPONDER_SLOT_COUNT EQUAL RESPONDER_HANDLE_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS and LIBSPDM_TPM_RESPONDER_HANDLES must have the same number of entries")
endif()

if(NOT RESPONDER_SLOT_COUNT EQUAL RESPONDER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS and LIBSPDM_TPM_RESPONDER_CERTCHAINS must have the same number of entries")
endif()

libspdm_validate_tpm_slot_ids("LIBSPDM_TPM_REQUESTER_SLOT_IDS" "${LIBSPDM_TPM_REQUESTER_SLOT_IDS}" REQUESTER_SUPPORTED_SLOT_MASK)
libspdm_validate_tpm_slot_ids("LIBSPDM_TPM_RESPONDER_SLOT_IDS" "${LIBSPDM_TPM_RESPONDER_SLOT_IDS}" RESPONDER_SUPPORTED_SLOT_MASK)

message(STATUS "TPM Configuration:")
message(STATUS "  Requester configured slots: ${LIBSPDM_TPM_REQUESTER_SLOT_IDS}")
message(STATUS "  Responder configured slots: ${LIBSPDM_TPM_RESPONDER_SLOT_IDS}")

# Generate keys.h content dynamically
set(KEYS_H_CONTENT "/**\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright Notice:\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright 2024-2026 DMTF. All rights reserved.\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} **/\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#pragma once\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* Auto-generated TPM handle configuration */\n\n")

# Add slot count and supported-slot mask macros
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_REQUESTER_SLOT_COUNT ${REQUESTER_SLOT_COUNT}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_REQUESTER_SUPPORTED_SLOT_MASK ${REQUESTER_SUPPORTED_SLOT_MASK}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_RESPONDER_SLOT_COUNT ${RESPONDER_SLOT_COUNT}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK ${RESPONDER_SUPPORTED_SLOT_MASK}\n\n")

# Generate requester handle definitions
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* TPM Requester Handles */\n")
math(EXPR REQUESTER_MAX_INDEX "${REQUESTER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${REQUESTER_MAX_INDEX})
    list(GET LIBSPDM_TPM_REQUESTER_SLOT_IDS ${INDEX} SLOT_ID)
    list(GET LIBSPDM_TPM_REQUESTER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_REQUESTER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_${SLOT_ID} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_${SLOT_ID} ${CERTCHAIN}\n")
endforeach()

set(KEYS_H_CONTENT "${KEYS_H_CONTENT}\n/* TPM Responder Handles */\n")
math(EXPR RESPONDER_MAX_INDEX "${RESPONDER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${RESPONDER_MAX_INDEX})
    list(GET LIBSPDM_TPM_RESPONDER_SLOT_IDS ${INDEX} SLOT_ID)
    list(GET LIBSPDM_TPM_RESPONDER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_RESPONDER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_${SLOT_ID} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_${SLOT_ID} ${CERTCHAIN}\n")
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
