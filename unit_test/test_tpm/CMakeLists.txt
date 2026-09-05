cmake_minimum_required(VERSION 3.5)

add_executable(test_tpm)

target_include_directories(test_tpm
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
)

target_sources(test_tpm
    PRIVATE
        test_tpm.c
)

target_link_libraries(test_tpm
    PRIVATE
        memlib
        debuglib
        cryptlib_openssl
        cmockalib
)

add_executable(test_tpm_cert_role)

target_include_directories(test_tpm_cert_role
    PRIVATE
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/unit_test/include
        ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
        ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
        ${LIBSPDM_DIR}/os_stub/include
        ${LIBSPDM_DIR}/os_stub
        ${CMAKE_BINARY_DIR}/os_stub/spdm_device_secret_lib_tpm
)

target_sources(test_tpm_cert_role
    PRIVATE
        test_tpm_cert_role.c
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm/read_pub_cert.c
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm/read_pub_cert_pqc.c
)

target_link_libraries(test_tpm_cert_role
    PRIVATE
        memlib
        debuglib
        cmockalib
)
