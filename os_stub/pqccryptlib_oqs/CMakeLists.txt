cmake_minimum_required(VERSION 3.5)

add_library(pqccryptlib_oqs STATIC "")

target_include_directories(pqccryptlib_oqs
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/pqccryptlib_oqs
        ${LIBSPDM_DIR}/os_stub/oqslib/include
)

target_sources(pqccryptlib_oqs
    PRIVATE
        mlkem.c
        mldsa_basic.c
        mldsa_cert.c
        mldsa_ext.c
        x509_cert.c
)
