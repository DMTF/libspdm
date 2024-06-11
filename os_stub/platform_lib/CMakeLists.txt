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
        time_linux.c
        watchdog.c
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_sources(platform_lib
        PRIVATE
        time_win.c
        watchdog.c
    )
else()
    target_sources(platform_lib
        PRIVATE
        time_sample.c
        watchdog.c
    )
endif()