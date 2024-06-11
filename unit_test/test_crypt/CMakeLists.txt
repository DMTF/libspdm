cmake_minimum_required(VERSION 3.5)

cmake_minimum_required(VERSION 3.5)

add_executable(test_crypt)

target_include_directories(test_crypt
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/test_crypt
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_crypt
    PRIVATE
        test_crypt.c
        hash_verify.c
        hmac_verify.c
        hkdf_verify.c
        aead_verify.c
        rsa_verify.c
        rsa_verify2.c
        dh_verify.c
        ec_verify.c
        ec_verify2.c
        ecd_verify.c
        ecd_verify2.c
        sm2_verify.c
        sm2_verify2.c
        rand_verify.c
        x509_verify.c
        os_support.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        target_compile_options(test_crypt PRIVATE /wd4819)
    endif()
endif()

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_link_libraries(test_crypt PRIVATE armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    target_link_libraries(test_crypt
        PRIVATE
            $<TARGET_OBJECTS:memlib>
            $<TARGET_OBJECTS:debuglib>
            $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
            $<TARGET_OBJECTS:rnglib>
            $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
            $<TARGET_OBJECTS:malloclib>
    )
else()
    target_link_libraries(test_crypt
        PRIVATE
            memlib
            debuglib
            ${CRYPTO_LIB_PATHS}
            rnglib
            cryptlib_${CRYPTO}
            malloclib
            spdm_crypt_lib
            spdm_crypt_ext_lib
        )
endif()
