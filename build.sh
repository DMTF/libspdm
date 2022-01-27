rm -rf ./build
mkdir build
cd build
 cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
 make copy_sample_key
 make
cd ..
