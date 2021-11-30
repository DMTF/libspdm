cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/fuzzing/test_spdm_responder_heartbeat_ack
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/library/spdm_common_lib
                    ${LIBSPDM_DIR}/library/spdm_responder_lib
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/library/spdm_secured_message_lib
                    ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
)

if(TOOLCHAIN STREQUAL "KLEE")
    INCLUDE_DIRECTORIES($ENV{KLEE_SRC_PATH}/include)
endif()

SET(src_test_spdm_responder_heartbeat_ack
    heartbeat_ack.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/algo.c
)

SET(test_spdm_responder_heartbeat_ack_LIBRARY
    memlib
    debuglib
    spdm_responder_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib_std
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_test_lib
    spdm_device_secret_lib_null
    spdm_device_secret_lib_sample
    cmockalib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_responder_heartbeat_ack
                   ${src_test_spdm_responder_heartbeat_ack}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_responder_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib_std>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_test_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_null>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
                   $<TARGET_OBJECTS:cmockalib>
    )
else()
    ADD_EXECUTABLE(test_spdm_responder_heartbeat_ack ${src_test_spdm_responder_heartbeat_ack})
    TARGET_LINK_LIBRARIES(test_spdm_responder_heartbeat_ack ${test_spdm_responder_heartbeat_ack_LIBRARY})
endif()
