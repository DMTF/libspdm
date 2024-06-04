cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
set(src_platform_lib_null
    time_linux.c
    watchdog.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
set(src_platform_lib_null
    time_win.c
    watchdog.c
)
endif()

add_library(platform_lib_null STATIC ${src_platform_lib_null})
