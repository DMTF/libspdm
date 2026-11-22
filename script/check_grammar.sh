#!/bin/bash

# Checks the grammar of the code comments and documentation that the commits since main add.

set -e

# Change directory to top of repository.
cd `dirname $0`
cd ../

# Reject first-person plural and second-person pronouns, and "my". For now only .github/, cmake/,
# doc/, include/, library/ and Markdown files are checked. CONTRIBUTING.md addresses contributors
# directly and codeql-analysis.yml is GitHub's template, so they are not checked.
words="we|our|ours|ourselves|let's|you|your|yours|yourself|yourselves|my|myself"
word_regex="(^|[^[:alnum:]_])($words)([^[:alnum:]_]|$)"
us_regex="(^|[^[:alnum:]_])us([^[:alnum:]_]|$)"
url_regex="https?://[^[:space:]]+"

# Returns success if the text uses one of the pronouns. URLs are ignored, and "us" counts only in
# lowercase, and not as microseconds, as in "(us)" or "10 us".
has_pronoun() {
    local text=$1
    local us_text

    while [[ $text =~ $url_regex ]]; do
        text=${text/"${BASH_REMATCH[0]}"/}
    done
    us_text=${text//\(us\)/}
    us_text=${us_text//[0-9] us/}

    shopt -s nocasematch
    if [[ $text =~ $word_regex ]]; then
        shopt -u nocasematch
        return 0
    fi
    shopt -u nocasematch

    [[ $us_text =~ $us_regex ]]
}

# Returns success if the line is in a fenced code block of a Markdown file, which quotes commands
# and tool output.
in_code_block() {
    [[ $1 == *.md ]] &&
        (( $(head -n $(($2 - 1)) "$1" | grep -c '^[[:space:]]*```') % 2 == 1 ))
}

git fetch origin main

# The diff is stored first so that set -e stops the script if git diff fails.
changes=$(git diff -U0 --no-color origin/main...HEAD -- \
              .github cmake doc include library '*.md' \
              ':!CONTRIBUTING.md' \
              ':!.github/workflows/codeql-analysis.yml')

exit_code=0
in_header=0
file=
line=0

# With no context lines, each hunk header gives the line number of the first added line.
while IFS= read -r diff_line; do
    if [[ $diff_line == "diff --git "* ]]; then
        in_header=1
    elif [[ $diff_line == "@@ "* ]]; then
        in_header=0
        line=${diff_line#*+}
        line=${line%%[, ]*}
    elif [[ $in_header == 1 ]]; then
        if [[ $diff_line == "+++ b/"* ]]; then
            file=${diff_line#+++ b/}
        fi
    elif [[ $diff_line == +* ]]; then
        if has_pronoun "${diff_line#+}" && ! in_code_block "$file" "$line"; then
            echo "$file:$line: ${diff_line#+}"
            exit_code=1
        fi
        line=$((line + 1))
    fi
done <<< "$changes"

if [[ $exit_code -ne 0 ]]; then
    echo "ERROR: Name the actor (libspdm, the Requester, the Responder, the Integrator) or use the" \
         "imperative instead of first- and second-person pronouns."
fi

exit $exit_code
