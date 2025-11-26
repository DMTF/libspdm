# /**
#  *  Copyright Notice:
#  *  Copyright 2025 DMTF. All rights reserved.
#  *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
#  **/

# automatic generate raw private key, raw public key and der format public key file for PQC after
# regenerating new key in sample_key.
# The generated raw data key for pqc will be consistent with the regenerating new key in sample_key.
# To execute: python raw_data_key_gen_pqc.py

import subprocess
import re

def extract_private_key(input_file, output_file = None):
    output = subprocess.check_output(["openssl", "pkey", "-in", input_file, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"priv:(.*?)pub:", output, re.DOTALL)
    if match:
        private_key = match.group(1).strip()
        private_key = private_key.replace(' ', '').replace(':', '').replace('\n', '')
        private_key_binary = bytes.fromhex(private_key)

        if output_file:
            with open(output_file, 'wb') as f:
                f.write(private_key_binary)

        return private_key_binary
    else:
        return None

def extract_public_key(input_file, output_file = None):
    output = subprocess.check_output(["openssl", "pkey", "-in", input_file, "-text", "-noout"])
    output = output.decode("utf-8")

    match = re.search(r"pub:(.*?)$", output, re.DOTALL)
    if match:
        public_key = match.group(1).strip()
        public_key = public_key.replace(' ', '').replace(':', '').replace('\n', '')
        public_key_binary = bytes.fromhex(public_key)

        if output_file:
            with open(output_file, 'wb') as f:
                f.write(public_key_binary)

        return public_key_binary
    else:
        return None

def convert_public_key_der(input_file, output_file):
    subprocess.run(["openssl", "pkey", "-in", input_file, "-pubout", "-out", output_file, "-outform", "DER"])

PQC_ALGO_LIST = [
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-192f",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-256f",
    "slh-dsa-sha2-256s",
    "slh-dsa-shake-128f",
    "slh-dsa-shake-128s",
    "slh-dsa-shake-192f",
    "slh-dsa-shake-192s",
    "slh-dsa-shake-256f",
    "slh-dsa-shake-256s",
]

KEY_NAME = [
    "end_requester",
    "end_responder"
]

for algo in PQC_ALGO_LIST:
    for key in KEY_NAME:
        input_path = "./{}/{}.key".format(algo, key)
        if extract_private_key(input_path, "{}.priv.raw".format(input_path)):
            print("get {} {} private key successfully".format(key, algo))
        else:
            print("get {} {} private key failed".format(key, algo))

        if extract_public_key(input_path, "{}.pub.raw".format(input_path)):
            print("get {} {} public key successfully".format(key, algo))
        else:
            print("get {} {} public key failed".format(key, algo))

        convert_public_key_der(input_path, "{}.pub.der".format(input_path))
        print("convert {} {} public key to DER format".format(key, algo))
