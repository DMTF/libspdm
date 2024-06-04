cmake_minimum_required(VERSION 3.5)

add_library(armbuild_lib STATIC "")

target_sources(armbuild_lib
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/div64.c
)