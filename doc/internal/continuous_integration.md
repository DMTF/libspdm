# Goals and Patterns for Continuous Integration

libspdm is designed to be configurable, both at compile time and at run time. Compile time
configuration enables an Integrator to include the minimal amount of code needed for their SPDM
implementation. Run time configuration enables an Integrator to ship an SPDM device that can operate
in a diversity of environments. However, such configurability places a burden on both the library
implementation and the tests that exercise and check that implementation. This document details
goals and patterns for the automated continuous integration pipeline.

## Compile Time Configuration Knobs

libspdm's compile time configuration knobs that can be adjusted within GitHub's runners include:
- Operating Systems
    - Windows
    - Linux
    - macOS
- Host Hardware (CMake `ARCH`)
    - ia32 (via WoW64)
    - x64
    - aarch64
- Toolchain (CMake `TOOLCHAIN`)
    - Visual Studio
    - Native GCC
    - MinGW GCC
    - CLANG
- Cryptography Library (CMake `CRYPTO`)
    - Mbed TLS
    - OpenSSL
- Build Target (CMake `TARGET`)
    - Release
    - Debug
- Other CMake Configuration Variables
    - `GCOV`
    - `STACK_USAGE`
    - `BUILD_LINUX_SHARED_LIB`
    - `X509_IGNORE_CRITICAL`
    - `DEVICE`
    - `DISABLE_TESTS`
    - `ENABLE_CODEQL`
    - `MARCH`
    - `USING_LTO`
- Code Configuration Macros
    - All of the macros found in
      https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h.

See also [GitHub's supported runners and hardware resources](https://docs.github.com/en/enterprise-cloud@latest/actions/reference/runners/github-hosted-runners#supported-runners-and-hardware-resources)
for public repositories. Ideally jobs should discover runner resources dynamically rather than
assume them.

Within the scope of libspdm's CMake build system, the operating system, host hardware, cryptography
library, toolchain, and build target are either detected by CMake or supplied as CMake variables.
Code configuration macros are communicated to libspdm via the `spdm_lib_config.h` header or through
compiler `CFLAGS`.

### Configuration Philosophy

In general, operating system, host hardware, cryptography library, toolchain, and build target
exercise the platform, while code configuration macros exercise the library. As such, they are
crossed sparsely where every platform is covered against a few configurations, and code
configurations are swept on the cheapest platform, where "cheapest" means a platform with high
availability and fast compilation and test execution times. An example would be Linux running on x64
hardware and compiling with GCC.

One exception to sparse platform combinations is that every combination of `ARCH` and `CRYPTO`
should be exercised, since cryptography libraries often utilize hardware-specific instructions.

### Legal Code Configurations

https://github.com/DMTF/libspdm/blob/main/include/internal/libspdm_macro_check.h specifies illegal
code configuration macros, and so test runners must avoid those configurations.

## Tests

### Unit Tests

The core unit tests are:
- test_spdm_requester
- test_spdm_responder
- test_spdm_crypt
- test_spdm_secured_message
- test_spdm_common
- test_crypt

and require no additional CMake or `CFLAGS` configuration settings.

Extended unit tests include:
- test_spdm_fips (`LIBSPDM_FIPS_MODE == 1`)
- test_spdm_tpm (`DEVICE == tpm`)

and do require additional configuration settings.

For any configuration run all core unit tests. Every job should produce a pass / fail signal. For
example, in the case where `DISABLE_TESTS` is asserted, the runner should check that no libspdm
tests were compiled. Reasonable runner timeouts should be specified so that if a test hangs then the
runner will detect the hang and produce a failing result. For example, if a passing test takes, in
its worst case, 20 minutes to build and run to completion, then a 30 minute timeout is reasonable.

## Test Utilities

### Sanitizers

Address (ASAN) and undefined behavior (UBSAN) sanitizers monitor the execution of production and
test code and flag illegal operations or behavior. For the purpose of continuous integration, they
should produce a pass / fail signal when illegal behavior is detected. In the case of UBSAN, this
may be accomplished by adding `UBSAN_OPTIONS=halt_on_error=1` so that the test exits with a non-zero
return code to alert the runner of a test failure.

### Reproducers

For all jobs, it is essential to be able to reproduce the results of a test, regardless of the
pass / fail status of the test. This is accomplished by capturing platform and code configuration
details, and capturing the state of the repository and its submodules. If the test is failing then
the runner should also generate a runnable reproduction script.

## Frequency and Coverage

Time estimates are given in wall clock time, from the start of the first job to the end of the last
job. They describe a best case in which the pipeline has the account's full concurrency allowance to
itself: 20 standard GitHub-hosted runners, with no slots consumed by other workflows and no time
spent queued. The estimates further assume that the worst case time to complete a single job is 20
minutes.

### Tier 1 - Pull Request / Push Coverage

Tests and configurations that run with every pull request or push to `main` should exercise the
standard defaults of the library running on native host systems. These are configurations that
follow, for example, the unaltered values in `spdm_lib_config.h`. They should include all of the
operating systems, host hardware, cryptography libraries, toolchains, and build targets listed
above, but need not be exhaustive in their combinations. In addition, the configurations should
alter coarse macros present in `spdm_lib_config.h` that greatly alter the size and behavior of the
library. Examples of such macros include `LIBSPDM_FIPS_MODE` and
`LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT`.

All tier 1 tests must pass before a pull request that targets production code or tests is merged
into `main` or any of the release branches.

For execution time, when all tests pass, the total test time should be less than 30 minutes.
