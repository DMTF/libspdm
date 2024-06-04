cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

set(src_memlib
    compare_mem.c
    copy_mem.c
    set_mem.c
    zero_mem.c
)

add_library(memlib STATIC ${src_memlib})
