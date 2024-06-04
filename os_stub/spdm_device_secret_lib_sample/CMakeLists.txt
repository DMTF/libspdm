cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_device_secret_lib_sample
    lib.c
    cert.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    add_compile_options(-DLIBSPDM_CPU_ARM)
endif()

add_library(spdm_device_secret_lib_sample STATIC ${src_spdm_device_secret_lib_sample})
