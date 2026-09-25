cmake_minimum_required(VERSION 3.16)

if(LIB_INSTALL_DIR)
else()
    set(LIB_INSTALL_DIR lib)
endif()

# Starting Mbed TLS 3.x release, mbedtls/library/CMakeLists.txt has dependency on
# link_to_source() function that is in mbedtls/CMakeLists.txt, so define
# link_to_source here. This shall be later expanded to add a link to the mbedtls
# source file from the build directory if required by libspdm.
function(link_to_source base_name)
endfunction(link_to_source)

# Mbed TLS is third-party code, so it is built without warning options. libspdm applies its own per
# target, but a project that adds this directory may set its options directory-wide. The -Wa, -Wl,
# and -Wp, pass-through options are kept.
get_directory_property(compile_options COMPILE_OPTIONS)
set(third_party_options "")
foreach(option IN LISTS compile_options)
    if(NOT option MATCHES "^-W([^alp]|[alp][^,])|^/[Ww]")
        list(APPEND third_party_options ${option})
    endif()
endforeach()
set_directory_properties(PROPERTIES COMPILE_OPTIONS "${third_party_options}")

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/mbedtls/library)

# mbedtls

if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedtls PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedtls PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
target_compile_options(mbedtls PRIVATE ${MBEDTLS_FLAGS})
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedtls PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedtls PRIVATE -DEFI32)
endif()

# mbedx509
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedx509 PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedx509 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
target_compile_options(mbedx509 PRIVATE ${MBEDTLS_FLAGS})
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedx509 PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedx509 PRIVATE -DEFI32)
endif()

# mbedcrypto
if(MBEDTLS_CONFIG_FILE)
else()
    target_compile_definitions(mbedcrypto PRIVATE -DMBEDTLS_CONFIG_FILE=<libspdm_mbedtls_config.h>)
endif()
target_include_directories(mbedcrypto PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include/mbedtls
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
)
target_compile_options(mbedcrypto PRIVATE ${MBEDTLS_FLAGS})
if(ARCH STREQUAL "x64")
    target_compile_definitions(mbedcrypto PRIVATE -DEFIx64)
elseif(ARCH STREQUAL "ia32")
    target_compile_definitions(mbedcrypto PRIVATE -DEFI32)
endif()

add_library(mbedtlslib INTERFACE)
target_link_libraries(mbedtlslib INTERFACE
    mbedx509
    mbedcrypto
)
