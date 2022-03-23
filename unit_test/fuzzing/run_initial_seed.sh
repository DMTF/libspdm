#!/bin/bash

# this script will run one program one time, with a known good seed, to ensure it can pass the flow without any exception.

export script_path="$(cd "$(dirname $0)";pwd)"
export libspdm_path=$script_path/../..
export initial_seeds=$libspdm_path/unit_test/fuzzing/seeds

if [[ $PWD!=$libspdm_path ]];then
    cd $libspdm_path
fi

if [ -d "build" ];then
    rm -rf build
fi

mkdir build
cd build

cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key
make -j`nproc`
cd bin
cp -r $initial_seeds ./

cmds=(
test_spdm_transport_mctp_encode_message
test_spdm_transport_mctp_decode_message
test_spdm_transport_pci_doe_encode_message
test_spdm_transport_pci_doe_decode_message
test_spdm_decode_secured_message
test_spdm_encode_secured_message
test_spdm_requester_encap_digests
test_spdm_requester_encap_certificate
test_spdm_requester_encap_challenge_auth
test_spdm_requester_encap_key_update
test_spdm_requester_encap_request
test_spdm_requester_get_version
test_spdm_requester_get_capabilities
test_spdm_requester_negotiate_algorithms
test_spdm_requester_get_digests
test_spdm_requester_get_certificate
test_spdm_requester_challenge
test_spdm_requester_get_measurements
test_spdm_requester_key_exchange
test_spdm_requester_finish
test_spdm_requester_psk_exchange
test_spdm_requester_psk_finish
test_spdm_requester_heartbeat
test_spdm_requester_key_update
test_spdm_requester_end_session
test_spdm_responder_encap_challenge
test_spdm_responder_encap_get_certificate
test_spdm_responder_encap_get_digests
test_spdm_responder_encap_key_update
test_spdm_responder_encap_response
test_spdm_responder_version
test_spdm_responder_capabilities
test_spdm_responder_algorithms
test_spdm_responder_digests
test_spdm_responder_certificate
test_spdm_responder_challenge_auth
test_spdm_responder_measurements
test_spdm_responder_key_exchange
test_spdm_responder_finish_rsp
test_spdm_responder_psk_exchange_rsp
test_spdm_responder_psk_finish_rsp
test_spdm_responder_heartbeat_ack
test_spdm_responder_key_update
test_spdm_responder_end_session
test_spdm_responder_if_ready
test_x509_certificate_check
)
for ((i=0;i<${#cmds[*]};i++))
do
    echo ++++++++++ ${cmds[$i]} starting ++++++++++
	echo ./${cmds[$i]} ./seeds/${cmds[$i]}/*.raw
	./${cmds[$i]} ./seeds/${cmds[$i]}/*.raw
done
