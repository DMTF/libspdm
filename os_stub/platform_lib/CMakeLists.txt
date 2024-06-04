cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND (NOT TOOLCHAIN STREQUAL "ARM_DS2022") AND (NOT TOOLCHAIN STREQUAL "RISCV_XPACK")  AND (NOT TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL"))
set(src_platform_lib
    time_linux.c
    watchdog.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
set(src_platform_lib
    time_win.c
    watchdog.c
)
else()
set(src_platform_lib
    time_sample.c
    watchdog.c
)
endif()

add_library(platform_lib STATIC ${src_platform_lib})
