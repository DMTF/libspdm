cmake_minimum_required(VERSION 3.5)

add_library(armbuild_lib STATIC "")

target_sources(armbuild_lib
    PRIVATE
        div64.c
)