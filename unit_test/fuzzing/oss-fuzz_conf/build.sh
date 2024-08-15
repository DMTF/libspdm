# SPDX-FileCopyrightText: 2022 Google LLC
#
# SPDX-License-Identifier: Apache-2.0

#!/bin/bash -eu

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

mkdir build
cd build
cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
make copy_sample_key
make
cp -r ./bin/* $OUT