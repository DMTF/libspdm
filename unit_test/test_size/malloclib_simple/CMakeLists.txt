cmake_minimum_required(VERSION 3.5)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_malloclib_simple
    malloclib.c
)

ADD_LIBRARY(malloclib_simple STATIC ${src_malloclib_simple})
