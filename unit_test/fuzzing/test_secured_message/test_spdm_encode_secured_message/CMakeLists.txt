cmake_minimum_required(VERSION 3.5)

add_executable(test_spdm_encode_secured_message)

target_include_directories(test_spdm_encode_secured_message
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/fuzzing/test_secured_message/test_spdm_encode_secured_message
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/library
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
        ${LIBSPDM_DIR}/os_stub/include
)

if(TOOLCHAIN STREQUAL "KLEE")
    target_include_directories(test_spdm_encode_secured_message
        PRIVATE
            $ENV{KLEE_SRC_PATH}/include
    )
endif()

target_sources(test_spdm_encode_secured_message
    PRIVATE
        spdm_encode_secured_message.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
        ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/algo.c
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_spdm_encode_secured_message
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:spdm_transport_mctp_lib>
            $<TARGET_OBJECTS:spdm_common_lib>
            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
            $<TARGET_OBJECTS:malloclib>
            $<TARGET_OBJECTS:spdm_crypt_lib>
            $<TARGET_OBJECTS:spdm_secured_message_lib>
            $<TARGET_OBJECTS:spdm_transport_test_lib>
            $<TARGET_OBJECTS:spdm_device_secret_lib_null>
    )
else()
    target_link_libraries(test_spdm_encode_secured_message
        PRIVATE
            memlib
            debuglib
            spdm_transport_mctp_lib
            spdm_common_lib
            ${CRYPTO_LIB_PATHS}
            rnglib
            cryptlib_${CRYPTO}
            malloclib
            spdm_crypt_lib
            spdm_secured_message_lib
            spdm_transport_test_lib
            spdm_device_secret_lib_null
    )
endif()
