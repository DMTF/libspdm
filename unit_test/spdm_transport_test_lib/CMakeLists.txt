cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/unit_test/spdm_transport_test_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
)

set(src_spdm_transport_test_lib
    common.c
    test.c
)

add_library(spdm_transport_test_lib STATIC ${src_spdm_transport_test_lib})
