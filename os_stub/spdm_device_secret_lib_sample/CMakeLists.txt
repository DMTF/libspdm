cmake_minimum_required(VERSION 3.5)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    add_compile_options(-DLIBSPDM_CPU_ARM)
endif()

add_library(spdm_device_secret_lib_sample STATIC "")

target_include_directories(spdm_device_secret_lib_sample
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_device_secret_lib_sample
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/lib.c
        ${CMAKE_CURRENT_LIST_DIR}/cert.c
)