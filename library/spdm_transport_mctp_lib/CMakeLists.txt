cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_transport_mctp_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_transport_mctp_lib
    common.c
    mctp.c
)

ADD_LIBRARY(spdm_transport_mctp_lib STATIC ${src_spdm_transport_mctp_lib})
