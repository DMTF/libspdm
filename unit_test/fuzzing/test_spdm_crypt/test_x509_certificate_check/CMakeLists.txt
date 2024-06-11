cmake_minimum_required(VERSION 3.5)

add_executable(test_x509_certificate_check)

target_include_directories(test_x509_certificate_check
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/fuzzing/test_responder/test_x509_certificate_check
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
        ${LIBSPDM_DIR}/os_stub/include
)

if(TOOLCHAIN STREQUAL "KLEE")
    target_include_directories(test_x509_certificate_check
        PRIVATE
            $ENV{KLEE_SRC_PATH}/include
    )
endif()

target_sources(test_x509_certificate_check
    PRIVATE
        x509_certificate_check.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_x509_certificate_check
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:spdm_responder_lib>
            $<TARGET_OBJECTS:spdm_common_lib>
            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
            $<TARGET_OBJECTS:malloclib>
            $<TARGET_OBJECTS:spdm_crypt_lib>
            $<TARGET_OBJECTS:spdm_secured_message_lib>
            $<TARGET_OBJECTS:spdm_transport_test_lib>
            $<TARGET_OBJECTS:spdm_device_secret_lib_null>
            $<TARGET_OBJECTS:platform_lib_null>
    )
else()
    target_link_libraries(test_x509_certificate_check
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
            spdm_secured_message_lib
            spdm_transport_test_lib
            spdm_device_secret_lib_null
            platform_lib_null
    )
endif()
