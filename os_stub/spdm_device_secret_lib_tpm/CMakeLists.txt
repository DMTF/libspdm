cmake_minimum_required(VERSION 3.5)

add_library(spdm_device_secret_lib_tpm STATIC "")

target_include_directories(spdm_device_secret_lib_tpm
    PRIVATE
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
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_device_secret_lib_tpm PRIVATE -DLIBSPDM_CPU_ARM)
endif()
