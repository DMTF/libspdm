cmake_minimum_required(VERSION 3.5)

set(src_armbuild_lib
    div64.c
)

add_library(armbuild_lib STATIC ${src_armbuild_lib})
