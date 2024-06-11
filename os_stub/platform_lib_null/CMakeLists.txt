cmake_minimum_required(VERSION 3.5)

add_library(platform_lib_null STATIC "")

target_include_directories(platform_lib_null
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_sources(platform_lib_null
        PRIVATE
            time_linux.c
            watchdog.c
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_sources(platform_lib_null
        PRIVATE
            time_win.c
            watchdog.c
    )

endif()

