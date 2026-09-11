cmake_minimum_required(VERSION 3.5)

add_library(debuglib STATIC "")

target_include_directories(debuglib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

if(CMAKE_SYSTEM_NAME STREQUAL "Zephyr")
    target_sources(debuglib
        PRIVATE
            debuglib_zephyr.c
    )
else()
    target_sources(debuglib
        PRIVATE
            debuglib.c
    )
endif()