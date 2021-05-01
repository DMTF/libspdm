cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/spdm_transport_test_lib
                    ${LIBSPDM_DIR}/library/spdm_common_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/unit_test/include
)

SET(src_spdm_transport_test_lib
    common.c
    test.c
)

ADD_LIBRARY(spdm_transport_test_lib STATIC ${src_spdm_transport_test_lib})
