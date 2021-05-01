cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/library/spdm_secured_message_lib 
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_secured_message_lib
    context_data.c
    encode_decode.c
    key_exchange.c
    session.c
)

ADD_LIBRARY(spdm_secured_message_lib STATIC ${src_spdm_secured_message_lib})
