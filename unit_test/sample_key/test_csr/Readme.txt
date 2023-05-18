openssl req -nodes -sha256 -newkey rsa:2048 -keyout rsa2048.key -outform DER -out rsa2048.csr
openssl req -nodes -sha384 -newkey rsa:3072 -keyout rsa3072.key -outform DER -out rsa3072.csr
openssl req -nodes -sha512 -newkey rsa:4096 -keyout rsa4096.key -outform DER -out rsa4096.csr


openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -nodes -newkey ec:param.pem -keyout ecc256.key -outform DER -out ecp256.csr -sha256

openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -newkey ec:param.pem -keyout ecc384.key -outform DER -out ecp384.csr -sha384

openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-521
openssl req -nodes -newkey ec:param.pem -keyout ecc521.key -outform DER -out ecp521.csr -sha512