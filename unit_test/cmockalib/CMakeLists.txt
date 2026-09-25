cmake_minimum_required(VERSION 3.16)

add_library(cmockalib STATIC "")

target_include_directories(cmockalib
    PRIVATE
        ${LIBSPDM_DIR}/unit_test/cmockalib
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
)

target_sources(cmockalib
    PRIVATE
        cmocka/src/cmocka.c
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_sources(cmockalib PRIVATE strdup.c)
endif()

# cmocka uses strdup() and strcasecmp(), which -std=c99 hides.
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_options(cmockalib PRIVATE -std=gnu99 -DHAVE_SIGNAL_H)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_compile_options(cmockalib PRIVATE -DHAVE_VSNPRINTF -DHAVE_SNPRINTF)
    if(NOT MSVC)
        target_compile_options(cmockalib PRIVATE -std=gnu99)
    endif()
endif()