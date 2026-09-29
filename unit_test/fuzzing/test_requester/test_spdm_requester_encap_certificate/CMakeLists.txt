cmake_minimum_required(VERSION 3.16)

add_executable(test_spdm_requester_encap_certificate)

target_include_directories(test_spdm_requester_encap_certificate
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/fuzzing/test_requester/test_spdm_requester_encap_certificate
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_${DEVICE}
        ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_requester_encap_certificate
    PRIVATE
        encap_certificate.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/algo.c
)

target_link_libraries(test_spdm_requester_encap_certificate
    PRIVATE
        memlib
        debuglib
        spdm_requester_lib
        spdm_common_lib
        ${CRYPTO_LIB_PATHS}
        rnglib
        platform_lib_null
        cryptlib_${CRYPTO}
        malloclib
        spdm_crypt_lib
        spdm_crypt_ext_lib
        spdm_secured_message_lib
        spdm_transport_test_lib
        spdm_device_secret_lib_${DEVICE}
        cmockalib
)
