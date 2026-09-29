cmake_minimum_required(VERSION 3.16)

add_executable(test_spdm_fips)

target_include_directories(test_spdm_fips
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_${DEVICE}
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_fips
    PRIVATE
        test_spdm_fips.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_link_libraries(test_spdm_fips PRIVATE armbuild_lib)
endif()

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
        spdm_device_secret_lib_${DEVICE}
)