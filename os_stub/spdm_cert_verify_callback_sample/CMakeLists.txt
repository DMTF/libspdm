cmake_minimum_required(VERSION 3.5)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    add_compile_options(-DLIBSPDM_CPU_ARM)
endif()

add_library(spdm_cert_verify_callback_sample STATIC "")

target_include_directories(spdm_cert_verify_callback_sample
    PUBLIC
        ${LIBSPDM_DIR}/os_stub/spdm_cert_verify_callback_sample
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_cert_verify_callback_sample
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/spdm_cert_verify_callback.c
)