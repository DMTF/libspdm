cmake_minimum_required(VERSION 3.5)

if(NOT ((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC")))
    add_executable(test_spdm_common)

    target_include_directories(test_spdm_common
        PRIVATE
            ${LIBSPDM_DIR}/unit_test/test_spdm_requester
            ${LIBSPDM_DIR}/include
            ${LIBSPDM_DIR}/unit_test/include
            ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
            ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
            ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
            ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
            ${LIBSPDM_DIR}/os_stub
    )

    target_sources(test_spdm_common
        PRIVATE
            test_spdm_common.c
            context_data.c
            support.c
            ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/common.c
            ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
            ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
    )

    target_link_libraries(test_spdm_common
        PRIVATE
            memlib
            debuglib
            spdm_responder_lib
            spdm_requester_lib
            spdm_common_lib
            ${CRYPTO_LIB_PATHS}
            rnglib
            cryptlib_${CRYPTO}
            malloclib
            spdm_crypt_lib
            spdm_crypt_ext_lib
            spdm_secured_message_lib
            spdm_device_secret_lib_sample
            spdm_transport_test_lib
            cmockalib
            platform_lib_null
    )

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
            target_compile_options(test_spdm_common PRIVATE /wd4819)
        endif()
    endif()
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_link_libraries(test_spdm_common PRIVATE armbuild_lib)
endif()
