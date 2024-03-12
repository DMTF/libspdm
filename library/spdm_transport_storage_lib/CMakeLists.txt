cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_spdm_transport_storage_lib
    libspdm_storage.c
)

ADD_LIBRARY(spdm_transport_storage_lib STATIC ${src_spdm_transport_storage_lib})
