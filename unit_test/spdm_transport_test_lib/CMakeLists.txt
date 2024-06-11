cmake_minimum_required(VERSION 3.5)

add_library(spdm_transport_test_lib STATIC "")

target_include_directories(spdm_transport_test_lib
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/spdm_transport_test_lib
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
)

target_sources(spdm_transport_test_lib
    PRIVATE
        common.c
        test.c
)
