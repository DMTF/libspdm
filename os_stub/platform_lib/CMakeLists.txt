cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
SET(src_platform_lib
    time_linux.c
    watchdog.c
    divtest.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_platform_lib
    time_win.c
    watchdog.c
)
endif()

ADD_LIBRARY(platform_lib STATIC ${src_platform_lib})
