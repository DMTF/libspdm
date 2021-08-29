cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_spdm_requester
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/library/spdm_common_lib
                    ${LIBSPDM_DIR}/library/spdm_requester_lib
                    ${LIBSPDM_DIR}/library/spdm_secured_message_lib
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
)

SET(src_test_spdm_common
    test_spdm_common.c
    context_data.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/common.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

SET(test_spdm_common_LIBRARY
    memlib
    debuglib
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_device_secret_lib
    spdm_transport_test_lib
    cmockalib
)

if(NOT ((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC")))
    ADD_EXECUTABLE(test_spdm_common ${src_test_spdm_common})
    TARGET_LINK_LIBRARIES(test_spdm_common ${test_spdm_common_LIBRARY})
endif()


