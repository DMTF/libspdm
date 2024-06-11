cmake_minimum_required(VERSION 3.5)

add_executable(test_spdm_fips)

target_include_directories(test_spdm_fips
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_fips
    PRIVATE
        test_spdm_fips.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(test_spdm_fips PRIVATE /wd4819)
    endif()
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_link_libraries(test_spdm_fips PRIVATE armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_spdm_fips
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:spdm_crypt_lib>
            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
            $<TARGET_OBJECTS:malloclib>
    )
else()
    target_link_libraries(test_spdm_fips
        PRIVATE
            memlib
            debuglib
            spdm_crypt_lib
            spdm_crypt_ext_lib
            ${CRYPTO_LIB_PATHS}
            cryptlib_${CRYPTO}
            rnglib
            malloclib
            cmockalib
            spdm_device_secret_lib_sample
    )
endif()