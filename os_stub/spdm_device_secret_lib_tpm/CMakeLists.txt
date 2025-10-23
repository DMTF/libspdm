cmake_minimum_required(VERSION 3.5)

add_library(spdm_device_secret_lib_tpm STATIC "")

target_include_directories(spdm_device_secret_lib_tpm
    PRIVATE
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_device_secret_lib_tpm
    PRIVATE
        lib.c
        sign.c
        chal.c
        measurment.c
        key_pair.c

        crypto_stub.c

        ../spdm_device_secret_lib_sample/read_priv_key_pem.c
        ../spdm_device_secret_lib_sample/read_priv_key_pem_pqc.c
        ../spdm_device_secret_lib_sample/read_priv_key_raw_data.c
        ../spdm_device_secret_lib_sample/read_priv_key_raw_data_pqc.c
        ../spdm_device_secret_lib_sample/read_pub_cert.c
        ../spdm_device_secret_lib_sample/read_pub_cert_pqc.c
        ../spdm_device_secret_lib_sample/read_pub_key_der.c
        ../spdm_device_secret_lib_sample/read_pub_key_der_pqc.c
        ../spdm_device_secret_lib_sample/read_special_cert.c
        # ../spdm_device_secret_lib_sample/set_cert.c
)
