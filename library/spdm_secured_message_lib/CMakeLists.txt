cmake_minimum_required(VERSION 3.5)

add_library(spdm_secured_message_lib STATIC "")

target_include_directories(spdm_secured_message_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_secured_message_lib
    PRIVATE
        libspdm_secmes_context_data.c
        libspdm_secmes_encode_decode.c
        libspdm_secmes_key_exchange.c
        libspdm_secmes_session.c
)