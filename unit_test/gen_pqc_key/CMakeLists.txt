cmake_minimum_required(VERSION 3.5)

cmake_minimum_required(VERSION 3.5)

add_executable(gen_pqc_key)

target_include_directories(gen_pqc_key
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/gen_pqc_key
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/oqslib/include
)

target_sources(gen_pqc_key
    PRIVATE
        gen_pqc_key.c
        os_support.c
)

target_link_libraries(gen_pqc_key
    PRIVATE
        memlib
        debuglib
        ${CRYPTO_LIB_PATHS}
        cryptlib_${CRYPTO}
        spdm_crypt_lib
        rnglib
        oqslib
        malloclib
)
