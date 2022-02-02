cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_SIGNAL_H")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/cmockalib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_CmockaLib
    cmocka/src/cmocka.c
)

ADD_LIBRARY(cmockalib STATIC ${src_CmockaLib})
TARGET_INCLUDE_DIRECTORIES(cmockalib PUBLIC
    ${LIBSPDM_DIR}/cmockalib/cmocka/include
    ${LIBSPDM_DIR}/cmockalib/cmocka/include/cmockery
)
