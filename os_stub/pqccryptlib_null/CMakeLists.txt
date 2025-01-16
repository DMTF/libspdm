cmake_minimum_required(VERSION 3.5)

add_library(pqccryptlib_null STATIC "")

target_include_directories(pqccryptlib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/pqccryptlib_null
        ${LIBSPDM_DIR}/os_stub/oqslib/include
)

target_sources(pqccryptlib_null
    PRIVATE
        mlkem.c
        mldsa_basic.c
        mldsa_cert.c
        mldsa_ext.c
)
