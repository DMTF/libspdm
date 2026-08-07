cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(spdm_requester_mctp)

target_sources(app PRIVATE
  src/main.c
  ${CMAKE_CURRENT_LIST_DIR}/../common/sample_ecp256.c
  ${CMAKE_CURRENT_LIST_DIR}/../common/sample_static_blob_store.c
  ${CMAKE_CURRENT_LIST_DIR}/../common/sample_support.c
  ${CMAKE_CURRENT_LIST_DIR}/../common/sample_set_cert.c
)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../common)
