cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
SET(src_sleeplib
    sleep_linux.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_sleeplib
    sleep_win.c
)
endif()

ADD_LIBRARY(sleeplib STATIC ${src_sleeplib})
