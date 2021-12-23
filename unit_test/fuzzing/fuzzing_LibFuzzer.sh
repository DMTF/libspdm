#!/bin/bash

# Before run this script, please install LLVM with: sudo apt install llvm, and install CLANG with: sudo apt install clang.
# If command 'screen' not found, please install with: sudo apt install screen.

if [ "$#" -ne "2" ];then
    echo "Usage: $0 <CRYPTO> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    #read -p "press enter to exit"
    exit
fi

if [[ $1 = "mbedtls" || $1 = "openssl" ]]; then
    echo "<CRYPTO> parameter is $1"
else
    echo "Usage: $0 <CRYPTO> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    exit
fi

echo "<duration> parameter is $2"
export duration=$2

echo "start fuzzing in Linux with LLVM LibFuzzer"

pkill screen

export script_path="$(cd "$(dirname $0)";pwd)"
export libspdm_path=$script_path/../..
export fuzzing_path=$libspdm_path/unit_test/fuzzing
export fuzzing_seeds=$libspdm_path/unit_test/fuzzing/seeds


if [[ $PWD!=$libspdm_path ]];then
    pushd $libspdm_path
    latest_hash=`git log --pretty="%h" -1`
    export fuzzing_out=$libspdm_path/unit_test/fuzzing/out_libfuzz_$1_$latest_hash
    export build_fuzzing=build_libfuzz_$1_$latest_hash
fi

if [ ! -d "$fuzzing_out" ];then
    mkdir $fuzzing_out
fi

rm -rf $fuzzing_out/*

if [[ "core" != `cat /proc/sys/kernel/core_pattern` ]];then
    # Here '123' is the sudo password, replace it with yours.
    echo '123' | sudo -S bash -c 'echo core >/proc/sys/kernel/core_pattern'
    pushd /sys/devices/system/cpu/
    echo '123' | sudo -S bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
    popd
fi

if [ -d "$build_fuzzing" ];then
    rm -rf $build_fuzzing
fi

mkdir $build_fuzzing
pushd $build_fuzzing

cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=$1 ..
make copy_sample_key
make
pushd bin

cmds=(
test_spdm_requester_get_version
test_spdm_responder_version
)
for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
	mkdir $fuzzing_out/${cmds[$i]}
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi
    screen -S ${cmds[$i]} -p 0 -X stuff "./${cmds[$i]} $fuzzing_seeds/${cmds[$i]} -rss_limit_mb=0 -timeout=10 -artifact_prefix=$fuzzing_out/${cmds[$i]}/"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'
    sleep $duration
    screen -S ${cmds[$i]} -X quit
    sleep 5
done
