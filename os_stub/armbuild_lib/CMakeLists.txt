# SPDX-FileCopyrightText: 2021-2024 DMTF
#
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.5)

add_library(armbuild_lib STATIC "")

target_sources(armbuild_lib
    PRIVATE
        div64.c
)