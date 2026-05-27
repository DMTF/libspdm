# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
#ENV http_proxy 'http://proxy.example.com:80/'
#ENV https_proxy 'https://proxy.example.com:80/'
RUN apt-get update && apt-get install -y make autoconf automake libtool curl
RUN NASM_VERSION=3.01 && \
	NASM_TAR_SHA256=aea120d4adb0241f08ae24d6add09e4a993bc1c4d9f754dbfc8020d6916c9be1 && \
	cd /tmp && \
	curl -fL -o nasm-${NASM_VERSION}.tar.gz https://www.nasm.us/pub/nasm/releasebuilds/${NASM_VERSION}/nasm-${NASM_VERSION}.tar.gz && \
	echo "${NASM_TAR_SHA256}  nasm-${NASM_VERSION}.tar.gz" | sha256sum -c - && \
	tar -xzf nasm-${NASM_VERSION}.tar.gz && \
	cd nasm-${NASM_VERSION} && \
	./configure --prefix=/usr/local && \
	make -j"$(nproc)" && \
	make install && \
	/usr/local/bin/nasm -v
#RUN git config --global http.proxy http://proxy.example.com:80/
#RUN git config --global https.proxy https://proxy.example.com:80/
COPY . $SRC/libspdm
WORKDIR $SRC/libspdm
COPY .clusterfuzzlite/build.sh $SRC/build.sh
