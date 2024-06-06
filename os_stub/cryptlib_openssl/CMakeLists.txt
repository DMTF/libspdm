cmake_minimum_required(VERSION 3.5)

add_library(cryptlib_openssl STATIC "")

target_include_directories(cryptlib_openssl
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub/cryptlib_openssl
        ${LIBSPDM_DIR}/os_stub/openssllib/include
        ${LIBSPDM_DIR}/os_stub/openssllib/openssl_gen
        ${LIBSPDM_DIR}/os_stub/openssllib/openssl/include
        ${LIBSPDM_DIR}/os_stub/openssllib/openssl/crypto/include
        ${LIBSPDM_DIR}/os_stub/openssllib/openssl
)

target_sources(cryptlib_openssl
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_aes_gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_chacha20_poly1305.c
        ${CMAKE_CURRENT_LIST_DIR}/cipher/aead_sm4_gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/der/der.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sha.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/hash/sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sha.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/hmac/hmac_sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sha.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sha3.c
        ${CMAKE_CURRENT_LIST_DIR}/kdf/hkdf_sm3.c
        ${CMAKE_CURRENT_LIST_DIR}/pem/pem.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/ec.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/ecd.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/dh.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/sm2.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/rsa_basic.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/rsa_ext.c
        ${CMAKE_CURRENT_LIST_DIR}/pk/x509.c
        ${CMAKE_CURRENT_LIST_DIR}/rand/rand.c
        ${CMAKE_CURRENT_LIST_DIR}/sys_call/crt_wrapper_host.c
)

target_compile_options(cryptlib_openssl PRIVATE ${OPENSSL_FLAGS})

if(ARCH STREQUAL "x64")
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_X64)
elseif(ARCH STREQUAL "ia32")
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_IA32)
elseif(ARCH STREQUAL "aarch64")
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_AARCH64)
elseif(ARCH STREQUAL "riscv32")
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_RISCV32)
elseif(ARCH STREQUAL "riscv64")
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_RISCV64)
elseif((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(cryptlib_openssl PRIVATE -DLIBSPDM_CPU_ARM)
else()
    message(FATAL_ERROR "Unknown ARCH")
endif()