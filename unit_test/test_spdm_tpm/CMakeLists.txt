cmake_minimum_required(VERSION 3.5)

add_executable(test_spdm_tpm)

target_include_directories(test_spdm_tpm
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${CMAKE_BINARY_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${LIBSPDM_DIR}/os_stub/spdm_cert_verify_callback_sample
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_tpm
    PRIVATE
        test_spdm_tpm.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(test_spdm_tpm PRIVATE /wd4819)
    endif()
endif()

target_link_libraries(test_spdm_tpm
    PRIVATE
        memlib
        debuglib
        spdm_crypt_lib
        ${CRYPTO_LIB_PATHS}
        cryptlib_${CRYPTO}
        rnglib
        malloclib
        cmockalib
        spdm_device_secret_lib_tpm
        spdm_cert_verify_callback_sample
        spdm_crypt_ext_lib
        spdm_common_lib
        spdm_secured_message_lib
        tss2-esys
        tss2-sys
        tss2-mu
        tss2-tctildr
        tss2-rc
)

