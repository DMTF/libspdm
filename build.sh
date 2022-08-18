rm -rf build

mkdir build

cd build

cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1" cmake -DARCH=x64 -DTOOLCHAIN=GCC  -DTARGET=Debug -DCRYPTO=mbedtls -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=0" cmake -DARCH=x64 -DTOOLCHAIN=GCC  -DTARGET=Debug -DCRYPTO=mbedtls -DGCOV=ON ..

# build (ubuntu-latest, mbedtls, x64, Release, LIBFUZZER, -DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1)

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=0" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Debug -DCRYPTO=mbedtls -DGCOV=ON ..
# 
# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Debug -DCRYPTO=mbedtls -DGCOV=ON ..



# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=0" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=0" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Debug -DCRYPTO=openssl -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Debug -DCRYPTO=openssl -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=0" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Release -DCRYPTO=openssl -DGCOV=ON ..

# cmake -E env CFLAGS="-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1" cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER  -DTARGET=Release -DCRYPTO=openssl -DGCOV=ON ..

make copy_sample_key

# make copy_seed

make -j`nproc`

cd bin

#  ./test_spdm_responder > NUL

#  ./test_spdm_requester > NUL

#  ./test_spdm_responder

# ./test_spdm_responder_chunk_get ./../../chunk_get.raw 

# ./test_spdm_responder_chunk_get ./../../unit_test/fuzzing/seeds/test_spdm_responder_chunk_get/chunk_get.raw 

# ./test_spdm_requester_chunk_get ./../../chunk_get3.raw 

#  ./test_spdm_responder_chunk_send_ack ./../../chunk_send.raw 

#  ./test_spdm_responder_chunk_send_ack ./../../timeout-6c5532372314a44156545e3907ac67700f0f498e

# ./test_spdm_requester_chunk_send ./../../challenge_auth11.raw

# cd ../

# rm -rf coverage_log

# mkdir coverage_log

# cd coverage_log

#     lcov --capture --directory /home/xiaohan/Xh_work/libspdm --output-file coverage.info

#     genhtml coverage.info --output-directory .