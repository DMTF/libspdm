cmake_minimum_required(VERSION 3.16)

add_executable(test_spdm_transport)

target_include_directories(test_spdm_transport
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_${DEVICE}
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_spdm_transport
    PRIVATE
        test_spdm_transport.c
        mctp.c
        pci_doe.c
        tcp.c
        storage.c
        error_test/mctp_err.c
        error_test/pci_doe_err.c
        error_test/tcp_err.c
        error_test/storage_err.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/common.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

target_link_libraries(test_spdm_transport
    PRIVATE
        memlib
        debuglib
        spdm_responder_lib
        spdm_requester_lib
        spdm_common_lib
        ${CRYPTO_LIB_PATHS}
        rnglib
        cryptlib_${CRYPTO}
        malloclib
        spdm_crypt_lib
        spdm_crypt_ext_lib
        spdm_secured_message_lib
        spdm_device_secret_lib_${DEVICE}
        spdm_transport_mctp_lib
        spdm_transport_pcidoe_lib
        spdm_transport_tcp_lib
        spdm_transport_storage_lib
        spdm_transport_test_lib
        cmockalib
        platform_lib_null
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    target_link_libraries(test_spdm_transport PRIVATE armbuild_lib)
endif()
