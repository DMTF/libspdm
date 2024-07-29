# SPDX-FileCopyrightText: 2021-2024 DMTF
#
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.5)

add_library(spdm_transport_mctp_lib STATIC "")

target_include_directories(spdm_transport_mctp_lib
    PRIVATE
        ${LIBSPDM_DIR}/include
)

target_sources(spdm_transport_mctp_lib
    PRIVATE
        libspdm_mctp_common.c
        libspdm_mctp_mctp.c
)