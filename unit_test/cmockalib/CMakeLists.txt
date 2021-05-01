cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_SIGNAL_H")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF")
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/cmockalib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
)

SET(src_CmockaLib
    cmocka/src/cmocka.c
)

ADD_LIBRARY(cmockalib STATIC ${src_CmockaLib})
