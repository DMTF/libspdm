cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub
)

set(src_spdm_crypt_ext_lib
    spdm_crypt_ext.c
)

add_library(spdm_crypt_ext_lib STATIC ${src_spdm_crypt_ext_lib})
