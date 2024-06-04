cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/os_stub/spdm_cert_verify_callback_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_cert_verify_callback_sample
    spdm_cert_verify_callback.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    add_compile_options(-DLIBSPDM_CPU_ARM)
endif()

add_library(spdm_cert_verify_callback_sample STATIC ${src_spdm_cert_verify_callback_sample})
