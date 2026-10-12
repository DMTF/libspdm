#!/bin/bash

# Checks if the messages of the commits since origin/main are encoded as ASCII.
# Signed-off-by, Co-authored-by, Reviewed-by, Acked-by and Tested-by lines are
# exempt, since they carry names.

set -e

# Change directory to top of repository.
cd `dirname $0`
cd ../

git fetch origin main

exit_code=0

for commit in $(git rev-list origin/main..HEAD)
do
    lines=$(git log -1 --format=%B $commit |
            grep -v -i -E '^(Signed-off-by|Co-authored-by|Reviewed-by|Acked-by|Tested-by):' |
            LC_ALL=C grep -P '[^\x00-\x7F]' || true)

    if [[ -n $lines ]]; then
        echo "ERROR: The message of commit $(git log -1 --format=%h $commit) is not encoded as ASCII."
        # Escape the non-ASCII bytes, since some, such as a byte order mark, are invisible.
        while IFS= read -r line
        do
            LC_ALL=C printf '    %q\n' "$line"
        done <<< "$lines"
        exit_code=1
    fi
done

exit $exit_code
