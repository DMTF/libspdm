cmake_minimum_required(VERSION 3.5)

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
        chal.c
        csr.c
        endpointinfo.c
        event.c
        key_pair.c
        meas.c
        psk.c
        read_priv_key_pem.c
        read_priv_key_raw_data.c
        read_pub_cert.c
        read_pub_key_der.c
        read_special_cert.c
        set_cert.c
        sign.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_device_secret_lib_sample PRIVATE -DLIBSPDM_CPU_ARM)
endif()