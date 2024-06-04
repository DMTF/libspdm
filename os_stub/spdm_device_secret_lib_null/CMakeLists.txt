cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_null
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
)

set(src_spdm_device_secret_lib_null
    lib.c
)

add_library(spdm_device_secret_lib_null STATIC ${src_spdm_device_secret_lib_null})
