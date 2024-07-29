# SPDX-FileCopyrightText: 2022 Google LLC
#
# SPDX-License-Identifier: Apache-2.0
FROM gcr.io/oss-fuzz-base/base-builder
#ENV http_proxy 'http://proxy.example.com:80/'
#ENV https_proxy 'https://proxy.example.com:80/'
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 https://github.com/DMTF/libspdm.git libspdm && cd libspdm && git submodule update --init    # or use other version control
WORKDIR libspdm
COPY build.sh $SRC/
