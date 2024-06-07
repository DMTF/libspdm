cmake_minimum_required(VERSION 3.5)

add_library(cryptstublib_dummy STATIC "")

target_include_directories(cryptstublib_dummy
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/os_stub/include
)

target_sources(cryptstublib_dummy
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/rand_dummy.c
        ${CMAKE_CURRENT_LIST_DIR}/timeclock_dummy.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cryptstublib_dummy PRIVATE -Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()