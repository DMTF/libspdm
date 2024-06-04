cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        add_compile_options(/wd4819)
    endif()
endif()

set(src_test_spdm_fips
    test_spdm_fips.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

set(test_spdm_crypt_LIBRARY
    memlib
    debuglib
    spdm_crypt_lib
    ${CRYPTO_LIB_PATHS}
    cryptlib_${CRYPTO}
    rnglib
    malloclib
    cmockalib
    spdm_device_secret_lib_sample
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    set(test_spdm_crypt_LIBRARY ${test_spdm_crypt_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    add_executable(test_spdm_fips
                   ${src_test_spdm_fips}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
    )
else()
    add_executable(test_spdm_fips ${src_test_spdm_fips})
    target_link_libraries(test_spdm_fips ${test_spdm_crypt_LIBRARY})
endif()
