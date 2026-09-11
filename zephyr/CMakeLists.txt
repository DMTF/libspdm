# Zephyr module build definition for libspdm.

if(NOT CONFIG_LIBSPDM)
  return()
endif()

set(LIBSPDM_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

zephyr_library_named(libspdm)

# Disable PQC support across libspdm and its os_stub sample libraries
# for the initial Zephyr port.
set(LIBSPDM_PORT_DEFS
  LIBSPDM_ML_DSA_44_SUPPORT=0
  LIBSPDM_ML_DSA_65_SUPPORT=0
  LIBSPDM_ML_DSA_87_SUPPORT=0
  LIBSPDM_ML_KEM_512_SUPPORT=0
  LIBSPDM_ML_KEM_768_SUPPORT=0
  LIBSPDM_ML_KEM_1024_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_128S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_128F_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_192S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_192F_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHA2_256F_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_128S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_128F_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_192S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_192F_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_256S_SUPPORT=0
  LIBSPDM_SLH_DSA_SHAKE_256F_SUPPORT=0
)

# Embedded-friendly libspdm sizing knobs. See the "Sizing" menu in
# zephyr/Kconfig for the defaults and the rationale behind them.
list(APPEND LIBSPDM_PORT_DEFS
  LIBSPDM_MAX_SESSION_COUNT=${CONFIG_LIBSPDM_MAX_SESSION_COUNT}
  LIBSPDM_MAX_CERT_CHAIN_SIZE=${CONFIG_LIBSPDM_MAX_CERT_CHAIN_SIZE}
  LIBSPDM_MAX_KEY_PAIR_COUNT=${CONFIG_LIBSPDM_MAX_KEY_PAIR_COUNT}
  LIBSPDM_MAX_PUBLIC_KEY_INFO_LEN=${CONFIG_LIBSPDM_MAX_PUBLIC_KEY_INFO_LEN}

  # Disable traditional asym algorithms we don't use now.
  LIBSPDM_RSA_SSA_2048_SUPPORT=0
  LIBSPDM_RSA_SSA_3072_SUPPORT=0
  LIBSPDM_RSA_SSA_4096_SUPPORT=0
  LIBSPDM_RSA_PSS_2048_SUPPORT=0
  LIBSPDM_RSA_PSS_3072_SUPPORT=0
  LIBSPDM_RSA_PSS_4096_SUPPORT=0
  LIBSPDM_ECDSA_P384_SUPPORT=0
  LIBSPDM_ECDSA_P521_SUPPORT=0
  LIBSPDM_SM2_DSA_P256_SUPPORT=0
  LIBSPDM_EDDSA_ED25519_SUPPORT=0
  LIBSPDM_EDDSA_ED448_SUPPORT=0
)
zephyr_compile_definitions(${LIBSPDM_PORT_DEFS})

# Expose the public headers to anything that links against the module.
zephyr_include_directories(
  ${LIBSPDM_DIR}/include
  ${LIBSPDM_DIR}/include/hal
  ${LIBSPDM_DIR}/os_stub/include
)

# Relax warnings that libspdm's source style trips on under Zephyr's
# stricter defaults. These are scoped to this library only.
zephyr_library_compile_options(
  -Wno-vla
  -Wno-unused-parameter
  -Wno-pointer-sign
  -Wno-incompatible-pointer-types
  -Wno-maybe-uninitialized
  -Wno-uninitialized
)

# ----------------------------------------------------------------------------
# Core libspdm sources (always needed)
# ----------------------------------------------------------------------------
file(GLOB LIBSPDM_COMMON_SRCS    ${LIBSPDM_DIR}/library/spdm_common_lib/*.c)
file(GLOB LIBSPDM_CRYPT_SRCS     ${LIBSPDM_DIR}/library/spdm_crypt_lib/*.c)
file(GLOB LIBSPDM_SECMSG_SRCS    ${LIBSPDM_DIR}/library/spdm_secured_message_lib/*.c)
file(GLOB LIBSPDM_CRYPTEXT_SRCS  ${LIBSPDM_DIR}/os_stub/spdm_crypt_ext_lib/*.c)

zephyr_library_sources(
  ${LIBSPDM_COMMON_SRCS}
  ${LIBSPDM_CRYPT_SRCS}
  ${LIBSPDM_SECMSG_SRCS}
  ${LIBSPDM_CRYPTEXT_SRCS}
)

if(CONFIG_LIBSPDM_REQUESTER)
  file(GLOB LIBSPDM_REQ_SRCS ${LIBSPDM_DIR}/library/spdm_requester_lib/*.c)
  zephyr_library_sources(${LIBSPDM_REQ_SRCS})
endif()

if(CONFIG_LIBSPDM_RESPONDER)
  file(GLOB LIBSPDM_RSP_SRCS ${LIBSPDM_DIR}/library/spdm_responder_lib/*.c)
  zephyr_library_sources(${LIBSPDM_RSP_SRCS})
endif()

# ----------------------------------------------------------------------------
# Transports - MCTP for Zephyr
# ----------------------------------------------------------------------------
if(CONFIG_LIBSPDM_TRANSPORT_MCTP)
  file(GLOB LIBSPDM_MCTP_SRCS ${LIBSPDM_DIR}/library/spdm_transport_mctp_lib/*.c)
  zephyr_library_sources(${LIBSPDM_MCTP_SRCS})
endif()

# ----------------------------------------------------------------------------
# OS HAL backends (Zephyr-flavoured)
# ----------------------------------------------------------------------------
zephyr_library_sources(
  ${LIBSPDM_DIR}/os_stub/memlib/compare_mem.c
  ${LIBSPDM_DIR}/os_stub/memlib/copy_mem.c
  ${LIBSPDM_DIR}/os_stub/memlib/set_mem.c
  ${LIBSPDM_DIR}/os_stub/memlib/zero_mem.c
  ${LIBSPDM_DIR}/os_stub/malloclib/malloclib.c
  ${LIBSPDM_DIR}/os_stub/platform_lib/time_zephyr.c
  ${LIBSPDM_DIR}/os_stub/platform_lib/watchdog.c
  ${LIBSPDM_DIR}/os_stub/rnglib/rng_zephyr.c
)

if(CONFIG_LIBSPDM_DEBUG_ENABLE)
  zephyr_library_sources(${LIBSPDM_DIR}/os_stub/debuglib/debuglib_zephyr.c)
else()
  zephyr_library_sources(${LIBSPDM_DIR}/os_stub/debuglib_null/debuglib.c)
endif()

# ----------------------------------------------------------------------------
# Crypto backend
# ----------------------------------------------------------------------------
if(CONFIG_LIBSPDM_CRYPTO_MBEDTLS)
  # Zephyr v4.4 ships mbedtls 4.x + TF-PSA-Crypto, so we simply use the
  # one provided by libspdm.
  set(LIBSPDM_MBEDTLS_DIR ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls)

  file(GLOB LIBSPDM_MBEDTLS_LIB_SRCS
       ${LIBSPDM_MBEDTLS_DIR}/library/*.c)
  # No threading or TLS protocol code -- libspdm uses only the crypto and
  # x509 facades. Filtering out the SSL/threading sources avoids dragging
  # in pthread / errno wrappers we'd otherwise have to stub.
  list(FILTER LIBSPDM_MBEDTLS_LIB_SRCS EXCLUDE REGEX "/(ssl|net|debug|threading|timing|version)[^/]*\\.c$")
  zephyr_library_sources(${LIBSPDM_MBEDTLS_LIB_SRCS})

  # Point every translation unit in this library (libspdm + bundled
  # mbedtls + sys_call wrappers) at the same libspdm-curated mbedtls
  # config so the MBEDTLS_PLATFORM_*_MACRO redirects to my_calloc/
  # my_free/my_printf/my_snprintf are consistent everywhere. That config
  # leaves the two *_TIME_ALT flags commented out because it assumes a
  # hosted time(); Zephyr has none, so enable them here. The matching
  # mbedtls_time()/mbedtls_ms_time() implementations are the
  # integrator's to supply -- see CONFIG_LIBSPDM_MBEDTLS_PLATFORM_TIME_ALT.
  zephyr_library_compile_definitions(
    MBEDTLS_CONFIG_FILE="libspdm_mbedtls_config.h"
  )
  if(CONFIG_LIBSPDM_MBEDTLS_PLATFORM_TIME_ALT)
    zephyr_library_compile_definitions(
      MBEDTLS_PLATFORM_MS_TIME_ALT
      MBEDTLS_PLATFORM_TIME_ALT
    )
  endif()
  zephyr_library_include_directories(
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
    ${LIBSPDM_MBEDTLS_DIR}/include
    ${LIBSPDM_MBEDTLS_DIR}/library
  )

  # libspdm's mbedtls config sets MBEDTLS_PLATFORM_{CALLOC,FREE}_MACRO
  # to my_{calloc,free} and MBEDTLS_PLATFORM_{PRINTF,SNPRINTF}_MACRO to
  # my_{printf,snprintf}. Pull in those wrappers so the bundled mbedtls
  # actually links -- the memory pair is referenced by asn1, bignum, ecp,
  # pem and others, the printf pair by the x509/oid code.
  file(GLOB CRYPTLIB_MBEDTLS_SYSCALL_SRCS
       ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/sys_call/*.c)
  # mem_allocation.c implements my_calloc/my_free on top of libspdm's
  # malloclib. crt_wrapper_host.c stubs my_printf/my_snprintf with
  # LIBSPDM_ASSERT: their only callers are the human-readable helpers
  # (mbedtls_x509_crt_info, mbedtls_x509_dn_gets,
  # mbedtls_oid_get_numeric_string, ...), which libspdm never invokes.
  zephyr_library_sources(${CRYPTLIB_MBEDTLS_SYSCALL_SRCS})

  # libspdm's wrappers around the mbedtls API.
  file(GLOB_RECURSE CRYPTLIB_MBEDTLS_SRCS
       ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls/*.c)
  list(FILTER CRYPTLIB_MBEDTLS_SRCS EXCLUDE REGEX "/sys_call/")
  # Skip PQC sources for now
  list(FILTER CRYPTLIB_MBEDTLS_SRCS EXCLUDE REGEX "_pqc\\.c$")
  list(FILTER CRYPTLIB_MBEDTLS_SRCS EXCLUDE REGEX "(mldsa|mlkem|slhdsa)")
  zephyr_library_sources(${CRYPTLIB_MBEDTLS_SRCS})

  zephyr_library_include_directories(
    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
  )

  # The bundled mbedtls trips on a handful of warnings Zephyr promotes
  # to errors. Scope these to the libspdm zephyr_library so they don't
  # leak to the rest of the application.
  zephyr_library_compile_options(
    -Wno-cast-qual
    -Wno-redundant-decls
    -Wno-unused-but-set-variable
    -Wno-unused-function
  )
elseif(CONFIG_LIBSPDM_CRYPTO_NULL)
  file(GLOB_RECURSE CRYPTLIB_NULL_SRCS
       ${LIBSPDM_DIR}/os_stub/cryptlib_null/*.c)
  zephyr_library_sources(${CRYPTLIB_NULL_SRCS})
  zephyr_library_include_directories(
    ${LIBSPDM_DIR}/os_stub/cryptlib_null
  )
endif()

# ----------------------------------------------------------------------------
# Sample device-secret library
# ----------------------------------------------------------------------------
if(CONFIG_LIBSPDM_SECRET_LIB_SAMPLE)
  file(GLOB SECRET_LIB_SAMPLE_SRCS
       ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample/*.c)
  # Drop set_cert.c as it uses POSIX open/write/close to persist new
  # certs to /tmp on a hosted OS. The three symbols it would define
  # instead are implemented by the Zephyr application.
  list(FILTER SECRET_LIB_SAMPLE_SRCS EXCLUDE REGEX "/set_cert\\.c$")
  zephyr_library_sources(${SECRET_LIB_SAMPLE_SRCS})
endif()

