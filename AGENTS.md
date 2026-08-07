# Guidance for AI Agents

## Specifications

When encountering this repository for the first time, thoroughly scan, analyze, and, if possible,
cache information from the specification with the latest Major.Minor.Patch version in
https://www.dmtf.org/dsp/DSP0274. Other Major.Minor specifications in
https://www.dmtf.org/dsp/DSP0274 may be scanned and analyzed as needed, always using the latest
Patch version.

Specifications in the following directories are to be scanned and analyzed as needed, always
using the latest Patch version.
- https://www.dmtf.org/dsp/DSP0277
- https://www.dmtf.org/dsp/DSP0276
- https://www.dmtf.org/dsp/DSP0275
- https://www.dmtf.org/dsp/DSP0289
- https://www.dmtf.org/dsp/DSP0287
- https://www.dmtf.org/dsp/DSP0286

## Conventions

Follow the conventions in
- https://github.com/DMTF/libspdm/blob/main/CONTRIBUTING.md
- https://github.com/DMTF/libspdm/blob/main/doc/programming_environment.md
- https://github.com/DMTF/libspdm/blob/main/doc/internal/library_template.md
- https://github.com/DMTF/libspdm/blob/main/doc/internal/unit_test_template.md

The words `Requester`, `Responder`, and `Integrator`, when used in the context of an SPDM Requester
or Responder and its Integrator, should always be capitalized.

## Project Configuration

The file https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h contains
default configuration values. These values may be altered by the library Integrator within the file
itself, through command line parameters, or by specifying a different configuration file via the
`LIBSPDM_CONFIG` macro. When code is generated it may be necessary to alter the configuration values
to ensure that the code builds correctly and passes tests.

## Code Generation

When code is generated for core library files in https://github.com/DMTF/libspdm/tree/main/library
then corresponding unit tests should also be generated to maintain code coverage.

### Code Comments

The core library code should be self-documenting. When code comments are necessary they should be
terse and convey information to a human that is difficult to infer from the code. Since the entire
repository is based on the SPDM specification (DSP0274), do not include the redundant
>Per DSP0274:

in any code comment unless its inclusion is sufficiently justified. Code comments for tests can
be more verbose and can reference sections and wording in the SPDM specification, as they help serve
as a form of documentation for the code-under-test.
