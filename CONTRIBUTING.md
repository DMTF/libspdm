# Contributing to libspdm

Thank you for your interest in contributing to libspdm, the DMTF reference
implementation of [SPDM](https://www.dmtf.org/standards/spdm).

This document describes the contribution process, the Developer Certificate of
Origin (DCO) that every commit must carry, and the rules for contributions that
were created or assisted by artificial intelligence (AI) tools.

## License

libspdm is licensed under the BSD 3-Clause License (see
[LICENSE.md](LICENSE.md)). By contributing, you agree that your contributions
are licensed under the same terms. New source files shall carry the standard
copyright and license header used throughout the repository.

## How to contribute

1. Fork the repository and create a topic branch for your change.
2. Make your change, following the existing libspdm coding style.
3. Add or update unit tests where applicable, and make sure the existing tests
   still pass.
4. Ensure each commit is signed off (see [Developer Certificate of
   Origin](#developer-certificate-of-origin-dco) below).
5. If any part of the contribution was generated or assisted by AI, add the
   required attribution (see [Use of AI assistance](#use-of-ai-assistance)).
6. Open a pull request against `main` and respond to review feedback.

Source code merges are agreed by the maintainers; any member may call for a vote
on a merge in accordance with the DMTF process.

## Developer Certificate of Origin (DCO)

As required by DSP4014 (DMTF Process for Working Bodies), DCO checking is enabled
for this repository and **all commits shall contain a DCO sign-off**. The DCO is
a legal statement, certified by a human, that you have the right to submit the
contribution under the project's license.

This project uses the standard Developer Certificate of Origin, Version 1.1. Its
full text is available at <https://developercertificate.org/>. In summary, by
signing off a commit you certify that you wrote the contribution or otherwise
have the right to submit it under the project's open source license, and that
you understand the contribution and your sign-off are public and kept on record.

### Signing off your commits

You certify the DCO by adding a `Signed-off-by` line to each commit message,
using your real name and an email address you can be reached at:

```
Signed-off-by: Jane Developer <jane.developer@example.com>
```

Git can add this line automatically with the `-s` (or `--signoff`) option:

```
git commit -s -m "your commit message"
```

The name and email in the `Signed-off-by` line must match the commit author.

## Use of AI assistance

Contributions may be developed with the help of AI coding assistants. When they
are, three rules apply. They follow from the fact that the DCO is a
certification that **only a human** can make, while DSP4014 separately requires
that generative-AI assistance be declared with the model and version of the tool
used. This mirrors the
[Linux kernel policy on AI coding assistants](https://docs.kernel.org/process/coding-assistants.html).

### 1. Do NOT attribute AI in `Signed-off-by`

An AI tool **must not** be named in a `Signed-off-by` line, and a contributor
must never sign off on behalf of an AI tool. The `Signed-off-by` line is the DCO
certification described above: it is a legal statement that a human makes and
takes responsibility for. A human contributor remains fully responsible for an
AI-assisted contribution, including:

- reviewing and understanding all AI-generated code;
- confirming it is correct and complies with the project's license; and
- certifying the DCO with their own `Signed-off-by` line.

### 2. Do NOT attribute AI in `Co-authored-by`

An AI tool **must not** be named in a `Co-authored-by` line. That trailer marks
a co-author of the commit, and authorship of a contribution to this project
rests with the human contributors who are responsible for it, not with the AI
tool that assisted them. Record AI involvement with `Assisted-by` instead (see
below).

### 3. DO attribute AI in `Assisted-by`

If a commit was generated or assisted by an AI tool, **declare it** with an
`Assisted-by` trailer that includes the tool's name and the model version, as
DSP4014 requires. Use the format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

- `AGENT_NAME` — the name of the AI tool or agent.
- `MODEL_VERSION` — the specific model and version used.
- `[TOOL1] [TOOL2]` — optional; additional specialized analysis tools.
  Everyday utilities (git, the compiler, make, editors, etc.) should be omitted.

Example commit trailer block:

```
Signed-off-by: Jane Developer <jane.developer@example.com>
Assisted-by: Claude Code:claude-opus-4-8
```

The `Signed-off-by` line is still required and is still the human contributor's
own certification; the `Assisted-by` line is added in addition to it, never
instead of it.

## References

- DSP4014 — DMTF Process for Working Bodies (see §6.4, *Source Code*):
  <https://www.dmtf.org/sites/default/files/DSP4014_2.15.0.pdf>
- DMTF policies: <https://www.dmtf.org/about-dmtf/policies>
- Linux kernel — Coding assistants:
  <https://docs.kernel.org/process/coding-assistants.html>
- Developer Certificate of Origin: <https://developercertificate.org/>
