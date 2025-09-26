# Unit Test Template

This document specifies naming schemes, patterns, and layouts for unit tests in
https://github.com/DMTF/libspdm/tree/main/unit_test.

## Test File Names

### Requester / Responder

Test file names for non-encapsulated messages take the form *message_name*.c, where `message_name`
is the request message for Requester tests and response message for Responder tests.

```
// Unit test file names for CHALLENGE request and CHALLENGE_AUTH response.
test_spdm_requester/challenge.c
test_spdm_responder/challenge_auth.c
```

Test file names for encapsulated messages take the form encap_*message_name*.c where `message_name`
is the encapsulated response message for Requester tests and encapsulated request message for
Responder tests.

```
// Unit test file names for encapsulated CHALLENGE_AUTH response and encapsulated CHALLENGE request.
test_spdm_requester/encap_challenge_auth.c
test_spdm_responder/encap_challenge.c
```

## Test Layout

Variables with external linkage (global variables) use the `g_` prefix. Variables at file scope use
the `m_` prefix.

In the patterns below, `message_name` is replaced with the name of the message. For example,
Requester testing of the `CHALLENGE` message yields

```C
int libspdm_req_challenge_test(void)
```

### Requester

#### Non-encapsulated Request Messages

```C
extern uint32_t g_some_global_variable;
static uint32_t m_some_file_scope_variable;

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
}

/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 **/
static void req_message_name_case1(void **state)
{
}

int libspdm_req_message_name_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(req_message_name_case1),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        true,
        send_message,
        receive_message,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
```

#### Encapsulated Response Messages

Naming pattern is the same as the pattern for the Responder's non-encapsulated messages with the
following differences:
- `rsp` becomes `req`
- `encap_` precedes `message_name`

For example
```C
int libspdm_req_encap_message_name_test(void)
```

### Responder

#### Non-encapsulated Response Messages

```C
/**
 * Test 1: describe the test case.
 * Expected behavior: describe the expected behavior of the unit under test.
 **/
static void rsp_message_name_case1(void **state)
{
}

int libspdm_rsp_message_name_test(void)
{
    const struct CMUnitTest test_cases[] = {
        cmocka_unit_test(rsp_message_name_case1),
    };

    libspdm_test_context_t test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    libspdm_setup_test_context(&test_context);

    return cmocka_run_group_tests(test_cases,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
```

#### Encapsulated Request Messages

Naming pattern is the same as the pattern for the Requester's non-encapsulated messages with the
following differences:
- `req` becomes `rsp`
- `encap_` precedes `message_name`

For example
```C
int libspdm_rsp_encap_message_name_test(void)
```
