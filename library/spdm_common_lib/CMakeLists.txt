cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_common_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_common_lib
    context_data.c
    context_data_session.c
    crypto_service.c
    crypto_service_session.c
    opaque_data.c
    support.c
)

ADD_LIBRARY(spdm_common_lib STATIC ${src_spdm_common_lib})
