# Slot Management Guide

SPDM 1.4 introduces the `SLOT_MANAGEMENT` request and `SLOT_MANAGEMENT_RESP` response (gated by
the `SLOT_MGMT_CAP` extended capability). These messages manage an endpoint's certificate slots as
storage elements, independent of the algorithm negotiated for the current connection. Unlike
`GET_CERTIFICATE`/`GET_DIGESTS`, which can only reach the slots of the currently selected algorithm,
slot management can reach the slots of every supported algorithm.

The slot management commands are not part of any transcript hash. Per the specification, for slot 0
they should only be issued in a trusted environment (such as secure manufacturing); for slots 1-7
they shall only be issued in a secure session or a trusted environment.

## Concepts: Algorithm, Bank, Slot, and Key Pair

Slot management is built around four related but independent concepts.

* **Algorithm** — an asymmetric signing algorithm (for example RSA2048, ECC384, or ML-DSA-65). One
  algorithm is negotiated per SPDM connection in the `ALGORITHMS` response.
* **Bank** — a set of certificate slots that all use one asymmetric algorithm. A Bank is addressed
  by a `BankID` (0 to 239, numbered consecutively from 0). The Responder selects a Bank from the
  negotiated algorithm; `GET_CERTIFICATE` and `CHALLENGE` operate only on the selected Bank.
* **Slot** — a storage element that holds one certificate chain. A `SlotID` (0 to 7) is scoped
  **within a Bank**, so a slot is addressed by the `(BankID, SlotID)` pair. The same `SlotID` in two
  different Banks refers to two different slots.
* **Key pair** — an asymmetric private/public key pair identified by a `KeyPairID` (1 to
  `TotalKeyPairs`), reported by `GET_KEY_PAIR_INFO`. A key pair has its own algorithm, and one key
  pair can be bound to more than one slot.

The relationships are:

```
   negotiated algorithm ──selects──▶ Bank (BankID)
                                      │  one asymmetric algorithm
                                      │  contains
                                      ▼
                          Slots (SlotID, scoped to the Bank)
                                      │  each slot holds a certificate chain
                                      │  and is associated with a
                                      ▼
                          Key pair (KeyPairID) ──has──▶ algorithm
```

A Bank fixes the algorithm, but it can contain multiple slots whose key pairs all use that same
algorithm. This is the [Multiple Asymmetric Key (multikey)](multikey.md) feature: the `SlotElement`
in a `GetBankDetails` response reports the `KeyPairID` associated with each slot (populated only when
`MULTI_KEY_CONN_RSP` is `true`).

## Enabling Slot Management

Slot management is compiled when `LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP` is set (the default). The
responder does not impose a fixed maximum Bank count; the `GetBankInfo` response is bounded only by
the response buffer size (and `BankID` is limited to 0-239 by the specification).

`SLOT_MGMT_CAP` is an SPDM 1.4 *extended* capability flag, negotiated over `GET_CAPABILITIES`. Set it
on the Responder before the connection with `libspdm_set_data` and `LIBSPDM_DATA_CAPABILITY_EXT_FLAGS`:

```c
data16 = SPDM_GET_CAPABILITIES_EXTENDED_RESPONSE_FLAGS_SLOT_MGMT_CAP;
libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_EXT_FLAGS, &parameter,
                 &data16, sizeof(data16));
```

## Requester API

After the connection has transitioned to `LIBSPDM_CONNECTION_STATE_NEGOTIATED` (SPDM 1.4 with
`SLOT_MGMT_CAP` negotiated), the Requester can call the following functions. Each takes the SPDM
context and an optional `session_id` (`NULL` for a normal message, non-`NULL` for a secured message).

| Function | SubCode |
| -------- | ------- |
| `libspdm_slot_management_get_supported_subcodes` | `SupportedSubCodes` |
| `libspdm_slot_management_get_bank_info`           | `GetBankInfo` |
| `libspdm_slot_management_get_bank_details`        | `GetBankDetails` |
| `libspdm_slot_management_get_certificate_chain`   | `GetCertificateChain` |
| `libspdm_slot_management_get_csr`                 | `GetCSR` |
| `libspdm_slot_management_manage_bank`             | `ManageBank` |
| `libspdm_slot_management_manage_slot`             | `ManageSlot` |
| `libspdm_slot_management_set_certificate`         | `SetCertificate` |

### Typical Requester flow

1. Call `libspdm_init_connection` and check that it is successful and that the negotiated version is
   at least 1.4.
2. Call `libspdm_slot_management_get_supported_subcodes` to discover which SubCodes the Responder
   supports. Each subsequent SubCode should be issued only if its bit is set in the returned bit map
   (the bit position is the SubCode value).
3. Call `libspdm_slot_management_get_bank_info` to enumerate the Banks and obtain each Bank's
   `SlotMask`.
4. For each Bank, call `libspdm_slot_management_get_bank_details` to read the Bank's algorithm fields
   and the per-slot `SlotElement`s (including the `KeyPairID` for each slot when the connection is
   multikey).
5. For each existing `(BankID, SlotID)`, call `libspdm_slot_management_get_certificate_chain` to read
   the certificate chain.
6. Optionally call `libspdm_slot_management_get_csr`, `libspdm_slot_management_manage_bank`,
   `libspdm_slot_management_manage_slot`, or `libspdm_slot_management_set_certificate`.

## Responder HAL

The Responder dispatches `SLOT_MANAGEMENT` in `libspdm_get_response_slot_management` and obtains the
device-specific information through the following HAL hooks (in
`hal/library/responder/slot_mgmt.h`). An Integrator implements these for the device.

| Hook | Purpose |
| ---- | ------- |
| `libspdm_read_slot_management_supported_subcodes` | Return the supported SubCode bit map. |
| `libspdm_read_slot_management_bank_info`           | Return the per-Bank info (BankID, SlotMask). |
| `libspdm_read_slot_management_bank_details`        | Return a Bank's algorithm fields and per-slot info, including each slot's certificate chain digest. |
| `libspdm_read_slot_management_certificate_chain`   | Return the certificate chain for a `(BankID, SlotID)`. The chain need not be provisioned into the SPDM context. |
| `libspdm_write_slot_management_bank`               | Configure a Bank (`ManageBank`). |
| `libspdm_write_slot_management_slot`               | Perform a slot operation such as erase (`ManageSlot`). |

The `GetCSR` and `SetCertificate` SubCodes reuse the existing `GET_CSR` and `SET_CERTIFICATE` HAL
hooks (`libspdm_gen_csr` and `libspdm_write_certificate_to_nvm`). The `SetCertificate` hook takes a
`bank_id` parameter to address a Bank; the legacy `SET_CERTIFICATE` flow, which has no Bank concept,
passes `LIBSPDM_SLOT_MANAGEMENT_BANK_ID_INVALID` to indicate that no Bank is addressed. The `GetCSR`
hook (`libspdm_gen_csr`) is unchanged and takes no `bank_id`: the CSR is generated from the
connection's negotiated algorithm, so Bank addressing would be redundant to the integrator.

## Sample Implementation

The `spdm_device_secret_lib_sample` provides a reference implementation in
`os_stub/spdm_device_secret_lib_sample/slot_management.c`. It models the Banks per the specification:

* The Banks are derived from the key pairs reported by `GET_KEY_PAIR_INFO`, grouped by their
  configured asymmetric algorithm — one Bank per distinct algorithm. This keeps the slot management
  responses consistent with `GET_KEY_PAIR_INFO`.
* A Bank can contain multiple slots, each associated with a different `KeyPairID`, as long as all of
  those key pairs use the Bank's algorithm.
* A slot's certificate chain and digest are read on demand for the Bank's algorithm; a slot is
  reported only if its certificate chain is readable in the current build.
* The supported SubCode bit map (`m_libspdm_slot_management_sub_code_bitmap`) and the Bank attributes
  (`m_libspdm_slot_management_bank_attributes`) are non-`static` globals that the Integrator can
  override.
* `ManageBank` `ConfigAlgo` succeeds (idempotently) when the Requester selects the Bank's existing
  algorithm, and is rejected for a different algorithm because the Bank's slots are provisioned.
* `ManageSlot` `Erase` removes a slot's certificate chain by writing a zero-length certificate NVM
  file (exactly as the base `SET_CERTIFICATE` erase does via `libspdm_write_certificate_to_nvm`),
  after which the slot no longer appears in `GetBankInfo`/`GetBankDetails` and `GetCertificateChain`
  for it fails. When `CERT_INSTALL_RESET_CAP` is advertised, the erase returns
  `ERROR(ResetRequired)`, mirroring `SET_CERTIFICATE`.
* A slot's populated/empty state is the single source of truth shared with `SET_CERTIFICATE`: it is
  derived on demand from the certificate store (a runtime-provisioned NVM file if present, otherwise
  the static certificate bundle), not cached in a separate flag. See [Command Sync](#command-sync).

## Command Sync

Several commands read or write the same underlying certificate/key state, so an implementation must
keep them consistent. The relevant commands are `GET_DIGESTS`, `GET_CERTIFICATE`, `SET_CERTIFICATE`,
`GET_CSR`, `GET_KEY_PAIR_INFO`/`SET_KEY_PAIR_INFO`, and the `SLOT_MANAGEMENT` SubCodes
(`GetBankInfo`, `GetBankDetails`, `GetCertificateChain`, `GetCSR`, `ManageBank`, `ManageSlot`,
`SetCertificate`).

The shared state is, per DSP0274:

* **Certificate chain per slot.** For the Bank selected by the negotiated algorithm, the
  `SLOT_MANAGEMENT` slots are the *same* slots that `GET_CERTIFICATE`/`GET_DIGESTS`/`CHALLENGE`
  operate on. A `SET_CERTIFICATE` (legacy or the `SLOT_MANAGEMENT` `SetCertificate` SubCode) or a
  `ManageSlot`/`SET_CERTIFICATE` `Erase` therefore changes what every one of those commands reports
  for that slot.
* **Key pair per slot.** `GET_KEY_PAIR_INFO` reports the key pairs and their associated certificate
  slots; `SET_KEY_PAIR_INFO` (`GenerateKeyPair`/`KeyPairErase`) changes them. The `SLOT_MANAGEMENT`
  Bank model is derived from `GET_KEY_PAIR_INFO` (one Bank per configured key-pair algorithm), so a
  key-pair change is reflected in the Bank/slot enumeration.
* **CSR state.** `GET_CSR` (legacy and the `SLOT_MANAGEMENT` `GetCSR` SubCode) share one outstanding
  CSR / `CSRTrackingTag` space, managed by the Responder as a device-global pool (1..7). A CSR is
  **not slot-scoped**: the `SLOT_MANAGEMENT` `GetCSR` ignores the `SlotID` field and the legacy
  `GET_CSR` has no slot address; a CSR is for a `KeyPairID`, not a slot.

### Slot state machine

A certificate slot is in exactly one of four states (DSP0274 "Certificate slots"). The state is
observable through `GET_DIGESTS` (`SupportedSlotMask`/`ProvisionedSlotMask`) and the `SLOT_MANAGEMENT`
`GetBankInfo`/`GetBankDetails` responses (`SlotMask`, `SlotAttributes.Provisioned`,
`CertificateInfo`). (`CHALLENGE_AUTH` carries a slot mask in `Param2`, but its bit is set only for the
"Exists with key and cert" state, not the `ProvisionedSlotMask` definition.) Several of these reported
values are **multikey-dependent** — see the per-field,
per-mode breakdown in the [slot management data model](slot_management_database.md#slot-states),
which is the authoritative reference for what each wire field reports in each state.

```
                          +-------------------------+
                          | 1. Does not exist       |
                          |    Supported=0          |   (fixed for the
                          +-------------------------+    connection)

   ------------------------------------------------------------------------
    exists (Supported=1)

                          +-------------------------+
                          | 2. Exists and empty     |
                          |    Provisioned=0         |
                          |    no key, no cert      |
                          +-------------------------+
                             |   ^
        GenerateKeyPair      |   |   KeyPairErase
        (SET_KEY_PAIR_INFO)  v   |   (SET_KEY_PAIR_INFO)
                          +-------------------------+
                          | 3. Exists with key      |
                          |    Provisioned=1 (mk)/0  |
                          |    CertificateInfo=0    |
                          |    AssocCertSlotMask=1  |
                          |    key, no cert         |
                          +-------------------------+
                             |   ^
        SetCertificate       |   |   Erase
        SET_CERTIFICATE      v   |   ManageSlot Erase / SET_CERTIFICATE Erase
                          +-------------------------+
                          | 4. Exists with key      |
                          |    and cert             |
                          |    Provisioned=1         |
                          |    CertificateInfo!=0(mk)|
                          |              /0 (non-mk) |
                          |    key + cert           |
                          +-------------------------+

   Notes:
   - "(mk)" marks a value that holds only in a multikey connection; the
     non-multikey value follows it. See the state table below and the data
     model for the full per-mode breakdown.
   - SetCertificate may also go directly 2 -> 4 (install cert when no separate
     key step is modeled). Erase keeps the key (4 -> 3); it only reaches 2 if
     the slot has no key.
```

| State | `DIGESTS.SupportedSlotMask` /<br>`SLOT_MANAGEMENT.BankInfo.SlotMask` | `DIGESTS.ProvisionedSlotMask` | `DIGESTS.CertificateInfo` /<br>`SLOT_MANAGEMENT.BankDetails.CertificateInfo` | `CHALLENGE_AUTH.Param2` /<br>`SLOT_MANAGEMENT.BankDetails.SlotAttributes.Provisioned` | `KEY_PAIR_INFO.AssocCertSlotMask` |
| ----- | --------------------------- | ----------------------------- | --------------------------------------------- | -------------------------------------------------------- | --------------------------------- |
| 1. Does not exist | 0 | 0 | 0 | 0 | 0 |
| 2. Exists and empty (multikey only) | 1 | 0 | 0 | 0 | 0 |
| 3. Exists with key | 1 | 1 (multikey) / 0 (non-multikey) | 0 | 0 | 1 |
| 4. Exists with key and cert | 1 | 1 | non-zero (multikey) / 0 (non-multikey) | 1 | 1 |

The mode-dependent cells follow DSP0274: `DIGESTS.ProvisionedSlotMask` sets a slot's bit for an
associated key (state 3) only in multikey (Table 41); `CertificateInfo` (`CertModel`) is 0 in a
non-multikey connection regardless of the stored cert (Table 42); `BankDetails.SlotAttributes.Provisioned`
is cert-only (set only when a certificate chain is present, so 0 for state 3 — Table 152); and
`KEY_PAIR_INFO.AssocCertSlotMask` carries the key↔slot association with no multikey gate, so it is 1
for states 3 and 4 in both modes. See the [data model](slot_management_database.md#slot-states) for
the full table.

State 2 ("exists and empty") only occurs in a multikey connection. A non-multikey endpoint has a
single key pair per supported algorithm (DSP0274 §"Certificates and certificate chains") that
implicitly backs every existing slot, so an existing slot always has a key — only states 1, 3, and 4
are reachable. (In the `DIGESTS` view a non-multikey state-3 slot reports `Provisioned = 0` and is
indistinguishable from state 2; the association is still observable via
`KEY_PAIR_INFO.AssocCertSlotMask`.)

The commands that read or change the state:

| Command | Effect on the slot state |
| ------- | ------------------------ |
| `GET_DIGESTS` | Read only. Reports a digest (and per-slot `KeyPairID`) for states 3-4; reserved/zero for 1-2. |
| `GET_CERTIFICATE` | Read only. Returns the chain in state 4; `ERROR(InvalidRequest)` otherwise. |
| `SLOT_MANAGEMENT` `GetBankInfo` / `GetBankDetails` / `GetCertificateChain` | Read only. Enumerate existing slots (states 2-4) and report each slot's attributes / chain. |
| `SLOT_MANAGEMENT` `GetCSR`, `GET_CSR` | Read only with respect to slot state (operate on CSR/key state, not the slot's certificate). |
| `SET_CERTIFICATE` (write), `SLOT_MANAGEMENT` `SetCertificate` | Install a certificate chain: 2 or 3 -> 4. |
| `SET_CERTIFICATE` (Erase), `SLOT_MANAGEMENT` `ManageSlot` `Erase` | Remove the certificate chain, keeping the key: 4 -> 3 (or -> 2 if the slot has no key). Does not erase the key. |
| `SET_KEY_PAIR_INFO` `GenerateKeyPair` | Associate/generate a key for a slot: 2 -> 3. Requires the key pair to have no associated certificate slot, so it does not act on a slot already in state 4. |
| `SET_KEY_PAIR_INFO` `KeyPairErase` | Remove the key: 3 -> 2. Requires the key pair to have no associated certificate slot. |
| `SLOT_MANAGEMENT` `ManageBank` `ConfigAlgo` | Does not change a slot's state directly, but requires no slot in the Bank to have a certificate provisioned (no slot in state 4; states 1/2/3 are allowed) to change the Bank's algorithm — else `ERROR(InvalidState)` (DSP0274 Table 141). On success the Responder clears all slot settings in the Bank. `ConfigAlgo` must select exactly one algorithm. |

State 1 is fixed for the life of the connection: a slot that does not exist stays non-existent.

### Current status

The sample implementation (`spdm_device_secret_lib_sample`) keeps these consistent as follows:

* **One certificate store.** `SET_CERTIFICATE`, the `SLOT_MANAGEMENT` `SetCertificate` SubCode, and
  `ManageSlot` `Erase` all go through `libspdm_write_certificate_to_nvm`, which writes a per-slot NVM
  file (`slot_id_<n>_cert_chain.der` for the BankID-less legacy flow, or
  `bank_id_<bbb>_slot_id_<n>_cert_chain.der` for a Bank-qualified write). The `SLOT_MANAGEMENT` read
  path (`GetCertificateChain`, and the slot enumeration in `GetBankInfo`/`GetBankDetails`) reads the
  same NVM file first and only falls back to the static certificate bundle when no runtime file
  exists. An erase writes a zero-length file, which the read path reports as empty without falling
  back. There is no separate in-memory "erased" flag, so the read and write paths cannot disagree.
* **Selected Bank aliases the legacy slot.** For the selected Bank, the read and erase paths also
  consult the BankID-less legacy file, so a base `SET_CERTIFICATE`/`Erase` on the in-use slot and a
  `SLOT_MANAGEMENT` read of that slot stay consistent.
* **Live served chain tracks the write.** `libspdm_update_local_cert_chain()` performs the NVM write **and** refreshes the
  in-memory `local_cert_chain_provision[]` store (via `libspdm_set_data(LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN)`)
  that `GET_CERTIFICATE`/`CHALLENGE`/`KEY_EXCHANGE` serve from, in the same HAL call — so a
  `SET_CERTIFICATE`/`Erase` takes effect on the served chain within the same boot (no reset/reload
  needed when `CERT_INSTALL_RESET_CAP` is not advertised). The `SLOT_MANAGEMENT` `SetCertificate`
  SubCode reuses that hook: for the selected Bank the in-memory chain is refreshed identically; a
  non-selected Bank is not reachable through `GET_CERTIFICATE`, so its chain lives only in NVM and
  is read back by `GetCertificateChain`. The AliasCert model assembles the complete chain (with the
  slot-0 Alias cert) at read time from that same store.
* **Reset semantics.** Both `SET_CERTIFICATE` and `ManageSlot` `Erase` return `ERROR(ResetRequired)`
  only when `CERT_INSTALL_RESET_CAP` is advertised, using the same `need_reset`/`is_busy` HAL
  signaling.
* **Banks track key pairs.** The Bank table is rebuilt from `GET_KEY_PAIR_INFO`, so the algorithms
  and slot associations reported by `SLOT_MANAGEMENT` match `GET_KEY_PAIR_INFO`.
* **Shared CSR path.** The `SLOT_MANAGEMENT` `GetCSR` SubCode reuses the `GET_CSR` HAL hook
  (`libspdm_gen_csr_ex`), so both share one CSR/`CSRTrackingTag` state.
