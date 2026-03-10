cmake_minimum_required(VERSION 3.16)

project(libspdm LANGUAGES C)

file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/VERSION.md CMAKE_INPUT_PROJECT_VERSION)
string(REPLACE " " "_" CMAKE_PROJECT_VERSION ${CMAKE_INPUT_PROJECT_VERSION})
string(REGEX REPLACE "[ ]*[A-Za-z]+[ ]*[A-Za-z ]+" "" PROJECT_VERSION ${CMAKE_INPUT_PROJECT_VERSION})

message("#########################")
message("## Build Configuration ##")
message("#########################")

set(LIBSPDM_DIR "${PROJECT_SOURCE_DIR}")

set(LIBSPDM_CRYPTO "openssl" CACHE STRING "Crypto backend: openssl or mbedtls")

option(LIBSPDM_TPM_SUPPORT "Enable TPM support in crypt_ext" OFF)
option(LIBSPDM_GCOV "Enable GCOV instrumentation" OFF)
option(LIBSPDM_STACK_USAGE "Enable stack usage instrumentation" OFF)
option(LIBSPDM_BUILD_SHARED_LIB "Build libspdm shared library" OFF)
option(LIBSPDM_X509_IGNORE_CRITICAL "Ignore unsupported critical extensions in certificates" OFF)
option(LIBSPDM_ENABLE_BINARY_BUILD "Use precompiled OpenSSL libraries" OFF)
option(LIBSPDM_BUILD_TESTS "Build unit tests" ON)

set(LIBSPDM_DEVICE "sample" CACHE STRING "Device secret implementation")

set(COMPILED_LIBCRYPTO_PATH "" CACHE PATH "Path to libcrypto")
set(COMPILED_LIBSSL_PATH "" CACHE PATH "Path to libssl")

message(STATUS "CMAKE_SYSTEM_NAME = ${CMAKE_SYSTEM_NAME}")
message(STATUS "CMAKE_BUILD_TYPE  = ${CMAKE_BUILD_TYPE}")
message(STATUS "LIBSPDM_CRYPTO    = ${LIBSPDM_CRYPTO}")
message(STATUS "LIBSPDM_DEVICE    = ${LIBSPDM_DEVICE}")

if(LIBSPDM_CRYPTO STREQUAL "mbedtls")

    add_compile_definitions(
        LIBSPDM_SM3_256_SUPPORT=0
        LIBSPDM_EDDSA_ED25519_SUPPORT=0
        LIBSPDM_EDDSA_ED448_SUPPORT=0
        LIBSPDM_SM2_DSA_P256_SUPPORT=0
        LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT=0
        LIBSPDM_AEAD_SM4_128_GCM_SUPPORT=0
        LIBSPDM_ML_DSA_44_SUPPORT=0
        LIBSPDM_ML_DSA_65_SUPPORT=0
        LIBSPDM_ML_DSA_87_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT=0
        LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT=0
        LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT=0
        LIBSPDM_ML_KEM_512_SUPPORT=0
        LIBSPDM_ML_KEM_768_SUPPORT=0
        LIBSPDM_ML_KEM_1024_SUPPORT=0
    )

elseif(LIBSPDM_CRYPTO STREQUAL "openssl")

    add_compile_definitions(
        LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT=0
        LIBSPDM_AEAD_SM4_128_GCM_SUPPORT=0
    )

else()
    message(FATAL_ERROR "Unknown crypto backend: ${LIBSPDM_CRYPTO}")
endif()

if(LIBSPDM_TPM_SUPPORT)

    if(NOT LIBSPDM_CRYPTO STREQUAL "openssl")
        message(FATAL_ERROR "TPM support requires OpenSSL backend")
    endif()

    add_compile_definitions(LIBSPDM_TPM_SUPPORT=1)

endif()

if(LIBSPDM_X509_IGNORE_CRITICAL)

    if(LIBSPDM_CRYPTO STREQUAL "openssl")
        add_compile_definitions(OPENSSL_IGNORE_CRITICAL=1)
    elseif(LIBSPDM_CRYPTO STREQUAL "mbedtls")
        add_compile_definitions(LIBSPDM_MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
    endif()

endif()

if(LIBSPDM_ENABLE_BINARY_BUILD)

    if(NOT LIBSPDM_CRYPTO STREQUAL "openssl")
        message(FATAL_ERROR "Binary build supported only with OpenSSL")
    endif()

    if(NOT COMPILED_LIBCRYPTO_PATH OR NOT COMPILED_LIBSSL_PATH)
        message(FATAL_ERROR "Binary build requires libcrypto and libssl paths")
    endif()

    set(CRYPTO_LIB_PATHS
        ${COMPILED_LIBCRYPTO_PATH}
        ${COMPILED_LIBSSL_PATH}
    )

else()

    set(CRYPTO_LIB_PATHS ${LIBSPDM_CRYPTO}lib)

endif()

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(LIBSPDM_DEBUG_ENABLE=0)
endif()

if(LIBSPDM_CRYPTO STREQUAL "mbedtls")
    add_subdirectory(os_stub/cryptlib_mbedtls)
elseif(LIBSPDM_CRYPTO STREQUAL "openssl")
    add_subdirectory(os_stub/cryptlib_openssl)
endif()

if(NOT LIBSPDM_ENABLE_BINARY_BUILD)

    if(LIBSPDM_CRYPTO STREQUAL "mbedtls")
        add_subdirectory(os_stub/mbedtlslib)
    elseif(LIBSPDM_CRYPTO STREQUAL "openssl")
        add_subdirectory(os_stub/openssllib)
    endif()

endif()

add_subdirectory(library/spdm_common_lib)
add_subdirectory(library/spdm_requester_lib)
add_subdirectory(library/spdm_responder_lib)
add_subdirectory(library/spdm_crypt_lib)
add_subdirectory(os_stub/spdm_crypt_ext_lib)
add_subdirectory(library/spdm_secured_message_lib)

add_subdirectory(library/spdm_transport_mctp_lib)
add_subdirectory(library/spdm_transport_pcidoe_lib)
add_subdirectory(library/spdm_transport_tcp_lib)
add_subdirectory(library/spdm_transport_storage_lib)

add_subdirectory(os_stub/memlib)
add_subdirectory(os_stub/debuglib)
add_subdirectory(os_stub/debuglib_null)
add_subdirectory(os_stub/rnglib)
add_subdirectory(os_stub/platform_lib)
add_subdirectory(os_stub/platform_lib_null)
add_subdirectory(os_stub/malloclib)

add_subdirectory(os_stub/spdm_device_secret_lib_${LIBSPDM_DEVICE})
add_subdirectory(os_stub/spdm_device_secret_lib_null)

add_subdirectory(os_stub/spdm_cert_verify_callback_sample)

if(LIBSPDM_BUILD_TESTS)
    add_subdirectory(unit_test)
endif()
