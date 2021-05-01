cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_null
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_device_secret_lib_null
    lib.c
)

ADD_LIBRARY(spdm_device_secret_lib_null STATIC ${src_spdm_device_secret_lib_null})
