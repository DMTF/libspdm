openssl req -nodes -sha256 -newkey rsa:2048 -keyout rsa2048.key -out rsa2048.csr
openssl req -nodes -sha384 -newkey rsa:3072 -keyout rsa3072.key -out rsa3072.csr
openssl req -nodes -sha512 -newkey rsa:4096 -keyout rsa4096.key -out rsa4096.csr


openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -nodes -newkey ec:param.pem -keyout ecc256.key -out ecp256.csr -sha256

openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -newkey ec:param.pem -keyout ecc384.key -out ecp384.csr -sha384

openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-521
openssl req -nodes -newkey ec:param.pem -keyout ecc521.key -out ecp521.csr -sha512