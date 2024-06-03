cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/spdm_transport_test_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
)

SET(src_spdm_transport_test_lib
    common.c
    test.c
)

ADD_LIBRARY(spdm_transport_test_lib STATIC ${src_spdm_transport_test_lib})
