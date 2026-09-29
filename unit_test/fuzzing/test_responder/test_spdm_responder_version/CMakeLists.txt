cmake_minimum_required(VERSION 3.16)

add_executable(test_spdm_responder_version)

target_include_directories(test_spdm_responder_version
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/fuzzing/test_responder/test_spdm_responder_version
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_responder_version
    PRIVATE
        version.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
)

target_link_libraries(test_spdm_responder_version
    PRIVATE
        memlib
        debuglib
        spdm_responder_lib
        spdm_common_lib
        ${CRYPTO_LIB_PATHS}
        rnglib
        cryptlib_${CRYPTO}
        malloclib
        spdm_crypt_lib
        spdm_crypt_ext_lib
        spdm_secured_message_lib
        spdm_transport_test_lib
        spdm_device_secret_lib_null
        platform_lib_null
)
