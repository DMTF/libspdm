cmake_minimum_required(VERSION 3.5)

add_library(platform_lib STATIC "")

target_include_directories(platform_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND (NOT TOOLCHAIN STREQUAL "ARM_DS2022") AND (NOT TOOLCHAIN STREQUAL "RISCV_XPACK")  AND (NOT TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL"))
    target_sources(platform_lib
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/time_linux.c
        ${CMAKE_CURRENT_LIST_DIR}/watchdog.c
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_sources(platform_lib
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/time_win.c
        ${CMAKE_CURRENT_LIST_DIR}/watchdog.c
    )
else()
    target_sources(platform_lib
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/time_sample.c
        ${CMAKE_CURRENT_LIST_DIR}/watchdog.c
    )
endif()