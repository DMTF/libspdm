cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_spdm_secured_message_lib
    libspdm_secmes_context_data.c
    libspdm_secmes_encode_decode.c
    libspdm_secmes_key_exchange.c
    libspdm_secmes_session.c
)

ADD_LIBRARY(spdm_secured_message_lib STATIC ${src_spdm_secured_message_lib})
