cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_watchdoglib
    watchdog.c
)

ADD_LIBRARY(watchdoglib STATIC ${src_watchdoglib})
