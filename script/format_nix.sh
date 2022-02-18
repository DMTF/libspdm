#!/bin/bash

# Executes the Uncrustify code beautifier.
# Beautification is needed to pass the CI/CD checks for a pull request.
# This script can be run from any directory within the libspdm repository.

# Check if uncrustify is present.
if ! command -v uncrustify &> /dev/null
then
    echo "ERROR: Unable to execute uncrustify."
    exit
fi

# cd to top of repository.
cd `dirname $0`
cd ../

# Run uncrustify and exclude submodules.
find -not -path "./unit_test/test_size/intrinsiclib/ia32/*" \
-not -path "./os_stub/mbedtlslib/mbedtls/*" \
-not -path "./os_stub/openssllib/openssl/*" \
-not -path "./unit_test/cmockalib/cmocka/*" \
 \( -name "*.c" -o -name "*.h" \) -exec uncrustify -q -c ./.uncrustify.cfg --replace --no-backup {} +
