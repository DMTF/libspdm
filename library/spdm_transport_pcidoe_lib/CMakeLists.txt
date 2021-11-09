cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_transport_pcidoe_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_transport_pcidoe_lib
    libspdm_doe_common.c
    libspdm_doe_pcidoe.c
)

ADD_LIBRARY(spdm_transport_pcidoe_lib STATIC ${src_spdm_transport_pcidoe_lib})
