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
        cipher/aead_aes_gcm.c
        cipher/aead_chacha20_poly1305.c
        cipher/aead_sm4_gcm.c
        der/der.c
        hash/sha.c
        hash/sha3.c
        hash/sm3.c
        hmac/hmac_sha.c
        hmac/hmac_sha3.c
        hmac/hmac_sm3.c
        kdf/hkdf_sha.c
        kdf/hkdf_sha3.c
        kdf/hkdf_sm3.c
        pem/pem.c
        pk/ec.c
        pk/ecd.c
        pk/dh.c
        pk/sm2.c
        pk/rsa_basic.c
        pk/rsa_ext.c
        pk/x509.c
        rand/rand.c
        sys_call/crt_wrapper_host.c
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