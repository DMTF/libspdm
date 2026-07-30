# Guidance for AI Agents

## Specifications

Specifications in the following URLs are to be scanned and analyzed as needed, always using the
latest Patch version.
- [Security Protocol and Data Model (SPDM)](https://www.dmtf.org/dsp/dsp0274)
- [Secured Messages Using SPDM](https://www.dmtf.org/dsp/DSP0277)
- [Secured Messages using SPDM over MCTP Binding](https://www.dmtf.org/dsp/DSP0276)
- [Security Protocol and Data Model (SPDM) over MCTP Binding](https://www.dmtf.org/dsp/DSP0275)
- [Security Protocol and Data Model (SPDM) Authorization](https://www.dmtf.org/dsp/DSP0289)
- [SPDM over TCP Binding](https://www.dmtf.org/dsp/DSP0287)
- [Security Protocol and Data Model (SPDM) to Storage Binding](https://www.dmtf.org/dsp/DSP0286)

Do not commit specification text or other derived files into the working tree.

## Conventions

Follow the conventions in
- `CONTRIBUTING.md`
- `doc/programming_environment.md`
- `doc/internal/library_template.md`
- `doc/internal/unit_test_template.md`

The words `Requester`, `Responder`, and `Integrator`, when used in the context of an SPDM Requester
or Responder and its Integrator, should always be capitalized.

## Repository Layout

- `library/`
    - The core library `.c` files.
- `include/`
    - `hal/library/`
        - API declarations that the Integrator must implement or that may be provided by libspdm in
          the `os_stub/` directory.
    - `industry_standard/`
        - Definitions for industry standard specifications.
    - `internal/`
        - Non-public files for use by the core library.
    - `library/`
        - Public files for use by the core library and the Integrator.
- `os_stub/`
    - Includes both sample code as well as possible production code. In particular this directory
      contains code to access the OpenSSL and Mbed TLS cryptography libraries.
- `unit_test/`
    - All files for testing the library, including fuzz testing.
- `doc/`
    - Both internal and public documentation for the repository.
- `script/`
    - The compliance checks that continuous integration runs, such as the copyright date and file
      encoding checks.

## Commits

Follow the AI-assistance rules in `CONTRIBUTING.md`. An AI tool must never be attributed in a
`Signed-off-by` or `Co-authored-by` trailer. The human contributor alone certifies the DCO with
their own `Signed-off-by` line. Instead, declare AI involvement with an `Assisted-by` trailer in the
form `Assisted-by: AGENT_NAME:MODEL_VERSION`. For example
`Assisted-by: Claude Code:claude-opus-4-8`.

Write the subject as a plain imperative sentence with no prefix, and name the issue a commit closes
with `Fix #N.` in the body. Every commit should build and pass its tests on its own.

## Project Configuration

The file `include/library/spdm_lib_config.h` contains default configuration values. These values may
be altered by the library Integrator within the file itself, through command line parameters, or by
specifying a different configuration file via the `LIBSPDM_CONFIG` macro. When code is changed it
may be necessary to alter the configuration values to ensure that the code builds correctly and
passes tests.

## Code Changes

When core library files in `library/` are generated or modified then the corresponding unit tests
should also be generated or updated to maintain code coverage. New files should include the DMTF
copyright header. Build the library and run the affected unit tests before considering a change
complete. See the Build section of `README.md` as well as `doc/build.md` and `doc/test.md`.

`LIBSPDM_ASSERT` deadloops by default, so a failing test hangs instead of exiting. Build with
`-DLIBSPDM_DEBUG_LIBSPDM_ASSERT_CONFIG=3`, as continuous integration does, or run the test under a
timeout.

The checks in `script/` gate every change and should be run before a commit.
- `check_copyright_date.sh`
    - Requires the copyright line to name the current year for every modified `.c` and `.h` file
      under the directories it lists.
- `check_encode.sh`
    - Requires the files under the directories it lists to be encoded in ASCII with LF line
      endings.
- `format_nix.sh`
    - Applies the uncrustify style in `.uncrustify.cfg`, and verifies without writing when given
      `--check`.

### Code Comments

The core library code should be self-documenting. When code comments are necessary they should be
terse and convey information to a human that is difficult to infer from the code. Since the entire
repository is based on the SPDM specification (DSP0274), do not include the redundant
`Per DSP0274:` in any code comment unless its inclusion is sufficiently justified. Code comments for
tests can be more verbose and can reference sections and wording in the SPDM specification, as they
help serve as a form of documentation for the code-under-test.

## Submodules

Do not modify code in any of the submodules listed in `.gitmodules` unless explicitly instructed to
do so.
