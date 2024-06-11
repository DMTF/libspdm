cmake_minimum_required(VERSION 3.5)

add_library(spdm_device_secret_lib_null STATIC "")

target_include_directories(spdm_device_secret_lib_null
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_null
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

target_sources(spdm_device_secret_lib_null
    PRIVATE
        lib.c
)