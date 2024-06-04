cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/unit_test/fuzzing/test_responder/test_spdm_responder_chunk_get
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

if(TOOLCHAIN STREQUAL "KLEE")
    include_directories($ENV{KLEE_SRC_PATH}/include)
endif()

set(src_test_spdm_responder_chunk_get
    chunk_get.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/algo.c
)

set(test_spdm_responder_chunk_get_LIBRARY
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
    spdm_device_secret_lib_sample
    cmockalib
    platform_lib_null
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    add_executable(test_spdm_responder_chunk_get
                   ${src_test_spdm_responder_chunk_get}
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
                   $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
                   $<TARGET_OBJECTS:cmockalib>
                   $<TARGET_OBJECTS:platform_lib_null>
    )
else()
    add_executable(test_spdm_responder_chunk_get ${src_test_spdm_responder_chunk_get})
    target_link_libraries(test_spdm_responder_chunk_get ${test_spdm_responder_chunk_get_LIBRARY})
endif()
