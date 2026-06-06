# Slot Management — Relational Data Model Proposal

## Purpose

The SPDM 1.4 certificate/key/slot state is exposed through several commands that today read and
write **independent stores** in the libspdm sample (`GET_DIGESTS`, `GET_CERTIFICATE`,
`SET_CERTIFICATE`, `GET_CSR`, `GET_KEY_PAIR_INFO`/`SET_KEY_PAIR_INFO`, and the `SLOT_MANAGEMENT`
SubCodes). Because each command has its own view, a change made through one command is not always
reflected by the others — see the [Known gaps](slot_management.md#known-gaps) in the slot management
guide (issues [#3638](https://github.com/DMTF/libspdm/issues/3638),
[#3645](https://github.com/DMTF/libspdm/issues/3645)).

This document proposes a single normalized data model — a small relational schema, expressed as C
structures — for the device secret store. With one schema and a set of integrity constraints, **any
change propagates to every command's view automatically**, because every command reads the same
tables. The C structures are implementation-ready: an Integrator (or the libspdm sample) can use
them directly. It is a device-backend data model, not an SPDM wire change.

## Why a relational model

The SPDM concepts map cleanly onto relations:

* a device has many **key pairs** (`KeyPairID`);
* a device has many **banks** (`BankID`), each fixing one asymmetric algorithm;
* a bank has many **slots** (`SlotID`, scoped to the bank);
* a slot may hold one **certificate chain**, and may have an outstanding **CSR**;
* a slot is associated with at most one key pair, and a key pair may back many slots.

The contradictions in the gaps are exactly the symptoms of an **un-normalized** store: the same fact
(which key pair backs a slot, what algorithm a slot uses, whether a slot has a cert) is recorded in
three places that can drift. Normalizing to one authoritative copy of each fact, with foreign keys
and triggers, removes the drift by construction.

## Entities and relationships

```
            +-------------+                                +----------------+
            |    bank     |   algorithm-agreement          |    key_pair    |
            | (BankID,    |- - - - - - - - - - - - - - - - | (KeyPairID,    |
            |  algo)      |   bank.algo == key_pair algo   |  current algo) |
            +-------------+                                +----------------+
                  | 1                                              | 1
                  | has                                            | backs
                  | *                                              | * (Shareable)
            +-------------+  1            0..1  +------------------+|
            |    slot     |---------------------|  slot_key_assoc  |+
            | (BankID,    |   has key assoc     | (BankID, SlotID, |
            |  SlotID)    |                     |  KeyPairID)      |
            +-------------+                     +------------------+
              | 1
      has cert|
       (0..1) |
              v
       +-----------+        +-------------------------------+
       | cert_chain|        |  csr  (device-global pool,    |
       +-----------+        |  keyed by CSRTrackingTag 1..7;|
                            |  identifies key by KeyPairID) |
                            +-------------------------------+
                                  : not slot-scoped -- GetCSR ignores SlotID
                                    (legacy GET_CSR has no slot address);
                                    stores neither bank_id nor slot_id

   (algorithm is a value type, libspdm_db_algo_t, embedded in bank.algo and
    key_pair.current_*_algo; it is not a separate stored table.)
```

* `bank` 1—* `slot` : a slot belongs to exactly one bank.
* `slot` 1—0..1 `slot_key_assoc` *—1 `key_pair` : a slot is associated with at most one key pair; a
  key pair may back many slots (`ShareableCap`). Modeled as an association table so the multikey
  many-to-one is explicit and constrained.
* `slot` 1—0..1 `cert_chain` : a slot holds at most one certificate chain.
* `csr` is a device-global pool keyed by `CSRTrackingTag` (1..7), not a per-slot relation; an entry
  identifies its key material by `KeyPairID`. It is **not slot-scoped** — `SLOT_MANAGEMENT GetCSR`
  ignores `SlotID` and the legacy `GET_CSR` has no slot address. An entry stores **neither `bank_id`
  nor `slot_id`**: the bank is derived from the key pair (`KeyPairID` → its unique bank), so storing
  it would be a second copy that could drift.
* `bank.algo` (the bank's configured algorithm) and `key_pair`'s current algorithm
  (`current_asym_algo` / `current_pqc_asym_algo`) are `libspdm_db_algo_t` values, not rows in a
  catalog table; a slot's key pair must use its bank's algorithm (the algorithm-agreement
  constraint, enforced by `libspdm_db_associate_slot_key()`).

## Slot states

This document refers to a certificate slot's "state 1..4" throughout. These are the four states
DSP0274 ("Certificate slots") defines for a slot, observable through the `SupportedSlotMask` /
`ProvisionedSlotMask` of `GET_DIGESTS`, the `Param2` slot mask of `CHALLENGE_AUTH` (set only for the
"Exists with key and cert" state), and the `SLOT_MANAGEMENT` `GetBankInfo`/`GetBankDetails` responses.
They are defined here so this document is self-contained:

A slot is in one of four states. The state itself is a device fact and is the **same in both
multikey and non-multikey** connections; the columns below give the value each wire field reports for
that state, naming each field by its full path. Columns whose value is identical across every state
are merged into one. The `DIGESTS.ProvisionedSlotMask` and the merged `CertificateInfo` columns show
where the *reported* value differs by mode (see the per-mode notes after the table):

| State | Name | Meaning | `DIGESTS.SupportedSlotMask` /<br>`SLOT_MANAGEMENT.BankInfo.SlotMask` | `DIGESTS.ProvisionedSlotMask` | `DIGESTS.CertificateInfo` /<br>`SLOT_MANAGEMENT.BankDetails.CertificateInfo` | `CHALLENGE_AUTH.Param2` /<br>`SLOT_MANAGEMENT.BankDetails.SlotAttributes.PROVISIONED` | `KEY_PAIR_INFO.AssocCertSlotMask` |
| ----- | ---- | ------- | --------------------------- | ----------------------------- | --------------------------------------------- | -------------------------------------------------------- | --------------------------------- |
| 1 | Does not exist | the slot is not present in the bank | 0 | 0 | 0 | 0 | 0 |
| 2 | Exists and empty | the slot exists but has no key and no certificate | 1 | 0 | 0 | 0 | 0 |
| 3 | Exists with key | a key pair is associated, but no certificate chain | 1 | 1 (multikey) / 0 (non-multikey) | 0 | 0 | 1 |
| 4 | Exists with key and cert | fully provisioned: key pair associated and a certificate chain present | 1 | 1 | non-zero (multikey) / 0 (non-multikey) | 1 | 1 |

> NOTE: The state-3 `DIGESTS.ProvisionedSlotMask` value `1 (multikey) / 0 (non-multikey)` is derived
> from the SPDM specification's `ProvisionedSlotMask` field (the `Param2` row of Table 41 — Successful
> DIGESTS response message format). That field sets the slot's bit if the slot has a certificate
> chain, or — only when `MULTI_KEY_CONN_REQ`/`RSP` is true — if it has an associated key pair. A
> state-3 slot has a key but no certificate, so the bit is set only in multikey mode. Note this
> differs from `SLOT_MANAGEMENT.BankDetails.SlotAttributes.PROVISIONED`, which is cert-only ("set to 1
> if the slot contains a certificate chain", Table 152) and so is 0 for state 3 in both modes.
> `KEY_PAIR_INFO.AssocCertSlotMask` carries the key↔slot association with no multikey gate, so it is
> 1 for states 3 and 4 in both modes.

DSP0274 §"Certificate slots" names this four-state model in the context of multikey, but the
underlying states exist regardless of mode; what changes is which states are *reachable* and how each
is *reported*:

* **Multikey** (`MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` true): all four states are reachable and
  fully reported. `KeyPairID` and `CertModel` are reported per slot, and `Provisioned` is 1 for
  state 3 (the associated-key clause of `ProvisionedSlotMask` applies).
* **Non-multikey** (both false): only states 1, 3, and 4 are reachable — **state 2 ("exists and
  empty") does not occur**, because a non-multikey endpoint has a single key pair per supported
  algorithm (DSP0274 §"Certificates and certificate chains") that implicitly backs every existing
  slot, so an existing slot always has a key. The per-slot association is **not reported in
  `DIGESTS`/`SlotElement`** — `KeyPairID` and `CertModel` are forced to 0 (DSP0274 Tables 41, 42, 152)
  and `ProvisionedSlotMask` reflects only the certificate, so a state-3 slot reports `Provisioned = 0`
  and is indistinguishable from state 2 in the `DIGESTS` view. The state-3 association is still
  observable, though, via `KEY_PAIR_INFO`.`AssocCertSlotMask`, which DSP0274 does not gate on multikey.

In this schema the state is **derived** from which `libspdm_db_t` array elements are present for the
slot (see [The slot state is derived, never stored](#the-slot-state-is-derived-never-stored)):
`slot[bank_id][slot_id]` not present = state 1; `slot` present only = state 2; `slot` +
`slot_key_assoc[bank_id][slot_id]` = state 3; `slot` + `slot_key_assoc` + `cert_chain[bank_id][slot_id]`
= state 4. This stored state is independent of multikey mode; what multikey changes is only how the
association is reported on the wire (see that section).

## Schema (C structures)

The schema is given as C structures so it can be used by an implementation directly. Each structure
is one "table"; the device store is a set of fixed-capacity arrays of these rows. Primary keys,
foreign keys, and constraints are stated in comments and enforced by the access functions (see
[Access API](#access-api)); the relational semantics are what matter, not the storage form.

Field names follow the DSP0274 wire field names where one exists, so the mapping in
[Mapping wire structures to the schema](#mapping-wire-structures-to-the-schema) is one-to-one. Bit
masks reuse the existing libspdm encodings (`SPDM_KEY_PAIR_CAP_*`, `SPDM_KEY_USAGE_CAPABILITIES_*`,
the Table 113/114 algorithm bitmaps, `SPDM_CERTIFICATE_INFO_CERT_MODEL_*`).

**Indexing and presence conventions** (used throughout):

* Rows are stored in dense arrays indexed by their key: `bank[bank_id]`, `slot[bank_id][slot_id]`,
  and (1-based key) `key_pair[key_pair_id - 1]`. The `csr` pool is indexed by `tracking_tag - 1`.
  The 1-based keys (`KeyPairID`, `CSRTrackingTag`) use **0 as the "none" sentinel**, so an index
  `key_pair_id - 1` / `tracking_tag - 1` is only valid after checking the key is non-zero (and within
  range). Every access function rejects a 0/out-of-range key before indexing, so the `- 1`
  expressions throughout this document presume that guard has already passed (never an underflow).
* A row also stores its own key (e.g. `slot.bank_id`/`slot.slot_id`) for serialization clarity and
  cross-checking; the stored key **must equal** the array index. It is redundant by construction,
  not a second source of truth — access functions never look a row up by its stored key.
* "Row exists" is the `present` flag for the sparse relations (`slot`, `slot_key_assoc`,
  `cert_chain`, `csr`) and the count (`num_banks`, `total_key_pairs`) for the dense contiguous ones
  (`bank`, `key_pair`).

```c
#define LIBSPDM_DB_FORMAT_VERSION   1    /* on-storage layout version of libspdm_db_t */
#define LIBSPDM_DB_MAX_KEY_PAIRS    16   /* device-defined: 1..TotalKeyPairs */
#define LIBSPDM_DB_MAX_BANKS        16   /* BankID 0..239; capacity is device-defined */
#define LIBSPDM_DB_MAX_SLOTS        SPDM_MAX_SLOT_COUNT   /* SlotID 0..7 per bank */
#define LIBSPDM_DB_MAX_CSR          7    /* CSRTrackingTag pool, 1..7 (DSP0274) */
/* For simplicity this model treats a PQC algorithm bitmap (Table 114) as 4 bytes, like the
 * traditional algorithm bitmap (Table 113), so both use uint32_t and need no length field. */

/* CSR transaction state (libspdm_db_csr_t.state) for the reset-required GET_CSR flow. */
#define LIBSPDM_DB_CSR_STATE_FREE          0   /* entry unused (present == false) */
#define LIBSPDM_DB_CSR_STATE_PENDING_RESET 1   /* tag reserved, GET_CSR returned ResetRequired;
                                                * der not yet generated (awaiting device reset) */
#define LIBSPDM_DB_CSR_STATE_READY         2   /* der generated and retrievable by tracking_tag */

/* ---- libspdm_db_algo_t: an asymmetric algorithm value -------------------------------------
 * This is a value TYPE, not a stored catalog table: an algorithm is a spec-defined wire bit
 * (DSP0274 Table 113 traditional / Table 114 PQC), not a device-specific row, so there is nothing to
 * normalize into a separate table and the schema embeds this value where an algorithm is needed.
 * At most one of asym_algo / pqc_asym_algo is non-zero; all-zero means "no/unconfigured algorithm".
 * Two libspdm_db_algo_t values are equal iff both fields are equal, which is how the bank<->key_pair
 * algorithm-agreement check compares them. */
typedef struct {
    uint32_t asym_algo;        /* Table 113 traditional bit, or 0 */
    uint32_t pqc_asym_algo;    /* Table 114 PQC bit, or 0 */
} libspdm_db_algo_t;

/* ---- key_pair: one row per KeyPairID (GET_KEY_PAIR_INFO, Table 111) -------------------------
 * KeyPairIDs are contiguous 1..total_key_pairs (0 is invalid: it means "no key pair"), so the store
 * uses a COUNT (total_key_pairs) rather than a per-row presence flag. Index this array by
 * (key_pair_id - 1) ONLY after checking key_pair_id != 0; a key_pair_id of 0 (e.g. an unassociated
 * slot) has no key_pair row and must not be used to index this array. */
typedef struct {
    uint8_t  key_pair_id;                 /* [RO] PK. Table 111 KeyPairID (== index + 1) */
    /* capabilities (Table 112) - [RO] immutable device facts */
    uint16_t capabilities;                /* [RO] SPDM_KEY_PAIR_CAP_* (GenKey/Erasable/CertAssoc/
                                           * KeyUsage/AsymAlgo/Shareable ...) */
    uint16_t key_usage_capabilities;      /* [RO] Table 111 KeyUsageCapabilities (key-usage bitmask) */
    uint32_t asym_algo_capabilities;      /* [RO] Table 111 AsymAlgoCapabilities (Table 113 bitmap) */
    uint32_t pqc_asym_algo_capabilities;  /* [RO] Table 111 PqcAsymAlgoCapabilities (Table 114 bitmap)*/
    /* current configuration - [RW] mutable via SET_KEY_PAIR_INFO */
    uint16_t current_key_usage;           /* [RW] Table 111 CurrentKeyUsage (subset of *_capabilities)*/
    uint32_t current_asym_algo;           /* [RW] Table 111 CurrentAsymAlgo (Table 113), 0 = unset */
    uint32_t current_pqc_asym_algo;       /* [RW] Table 111 CurrentPqcAsymAlgo (Table 114), 0 = unset */
    /* key material (state of the key itself) - [RW] via SET_KEY_PAIR_INFO GenerateKeyPair/KeyPairErase */
    uint16_t public_key_info_len;         /* [RW] Table 111 PublicKeyInfoLen; 0 => key absent/ungen */
    uint8_t  public_key_info[LIBSPDM_DB_PUBKEY_INFO_MAX];     /* [RW] Table 111 PublicKeyInfo (DER) */
    /* INVARIANTS (enforced by access fns):
     *   - current_key_usage is a subset of key_usage_capabilities
     *   - at most one bit total across current_asym_algo + current_pqc_asym_algo
     *   - that one current bit is within asym/pqc_asym_algo_capabilities
     *   - public_key_info_len == 0  <=>  no slot_key_assoc may reference this key pair
     *   - a key pair maps to AT MOST ONE bank: the bank whose algo equals the key pair's current
     *     algorithm. This holds because configured-bank algorithms are unique (see bank). An
     *     unconfigured key pair (current_*_algo all-zero) maps to NO bank, and "the key pair's
     *     bank" (used by AssocCertSlotMask) is undefined for it -- such a key pair must have no
     *     slot_key_assoc row, which is guaranteed by the bank-algorithm-match check in
     *     libspdm_db_associate_slot_key() (an all-zero key-pair algo cannot match a configured
     *     bank, so association is rejected).
     *   NOTE: AssocCertSlotMask is NOT stored here; it is derived from slot_key_assoc
     *         (see mapping), so it cannot drift from the slot view. The bank for that derivation is
     *         the (unique) bank whose algo matches this key pair's current algorithm. */
} libspdm_db_key_pair_t;

/* ---- bank: one row per BankID (GetBankInfo Table 150 / GetBankDetails Table 151) -----------
 * Per DSP0274, BankIDs are contiguous 0..(num_banks-1) (max 239), so the store uses a COUNT
 * (num_banks, the analogue of GetBankInfo.NumBankElements) rather than a per-row presence flag.
 * Index this array by bank_id.
 *
 * Uniqueness: at most one bank per algorithm (DSP0274 AvailableAsymAlgo clears bits already assigned
 * to another bank). This applies only to CONFIGURED banks: an all-zero algo means "not yet
 * configured" and is the NULL sentinel, so it is EXCLUDED from the uniqueness rule -- any number of
 * banks may be unconfigured (algo all-zero) at once. Concretely: for any two banks i != j with
 * non-all-zero algo, algo[i] != algo[j]. */
typedef struct {
    uint8_t           bank_id;            /* [RO] PK. Table 150/151 BankID (== index) */
    libspdm_db_algo_t algo;               /* [RW] the bank's CurrentAsymAlgo/CurrentPqcAsymAlgo
                                           * (libspdm_db_algo_t value); all-zero => not configured.
                                           * Written by ManageBank ConfigAlgo. */
    uint32_t          asym_algo_capabilities;     /* [RO] Table 151 AsymAlgoCapabilities: the
                                           * algorithms this bank can be configured to (the bank's
                                           * algo is one of these bits). A device fact, captured from
                                           * the bank's key pair(s); ManageBank ConfigAlgo never
                                           * changes it. */
    uint32_t          pqc_asym_algo_capabilities;  /* [RO] Table 151 PqcAsymAlgoCapabilities. */
    uint8_t           bank_attributes;    /* [RO] Table 151 BankAttributes (SPDM_SLOT_MANAGEMENT_BANK_
                                           * ATTRIBUTE_*). Only the non-derived CONFIG_ALGO bit is
                                           * stored; the SELECTED bit is NOT stored (derived per
                                           * connection as bank.algo == negotiated algo) and is
                                           * OR'd in at read time. */
} libspdm_db_bank_t;

/* ---- slot: one row per existing (BankID, SlotID) -------------------------------------------
 * Primary key: (bank_id, slot_id). FK: bank_id -> bank.
 * Row EXISTS  <=> slot state is "exists" (states 2/3/4). No row <=> state 1 "does not exist". */
typedef struct {
    uint8_t bank_id;                      /* [RO] PK part, FK->bank */
    uint8_t slot_id;                      /* [RO] PK part (0..7) */
    bool    present;                      /* [RO] false => slot does not exist in this bank (state 1);
                                           * slot existence is a device fact, fixed for the connection */
    uint8_t slot_attributes;              /* [RO] Table 152 SlotAttributes (SPDM_SLOT_MANAGEMENT_SLOT_
                                           * ATTRIBUTE_*). Only the non-derived WRITE_PROTECTED bit
                                           * is stored; the PROVISIONED bit is NOT stored (derived
                                           * as cert_chain[bank_id][slot_id].present) and is OR'd in at read. */
    bool    modifiable;                   /* [RO] BankElement.ModifiableSlotMask bit: erasable+writable */
} libspdm_db_slot_t;

/* ---- slot_key_assoc: slot <-> key pair (the multikey relation) -----------------------------
 * Primary key: (bank_id, slot_id) -> a slot has AT MOST ONE key pair.
 * FK: (bank_id, slot_id) -> slot ; key_pair_id -> key_pair.
 * A key pair may back MANY slots (Shareable). This single table is the ONE authoritative copy
 * of the association; all three wire views are projections of it (see mapping), so:
 *   AssocCertSlotMask(key_pair_id) = { slot_id : assoc row has this key_pair_id, same bank }
 *   SlotElement.KeyPairID(slot)  = assoc row's key_pair_id
 *   GET_DIGESTS.KeyPairID[slot]  = assoc row's key_pair_id
 * They cannot disagree because they read the same rows (resolves #3638).
 *
 * Key usage is NOT stored here. Per DSP0274, key usage is configured per key pair
 * (KEY_PAIR_INFO.CurrentKeyUsage; the only writer is SET_KEY_PAIR_INFO.DesiredKeyUsage). A slot's
 * key usage is therefore the CurrentKeyUsage of its associated key pair, so SlotElement.KeyUsage and
 * GET_DIGESTS.KeyUsageMask[slot_id] are DERIVED from key_pair[key_pair_id-1].current_key_usage. Storing a
 * per-slot copy would be redundant and could drift (especially with ShareableCap, where many slots
 * share one key pair and must report that one key usage). */
typedef struct {
    uint8_t  bank_id;                     /* [RO] PK part, FK->slot (echoes the array index) */
    uint8_t  slot_id;                     /* [RO] PK part, FK->slot (echoes the array index) */
    bool     present;                     /* [RW] false => slot has no associated key (state 2) */
    uint8_t  key_pair_id;                 /* [RW] FK->key_pair. SlotElement/GET_DIGESTS KeyPairID */
} libspdm_db_slot_key_assoc_t;

/* ---- cert_chain: the certificate chain in a slot (0..1 per slot) ---------------------------
 * Primary key: (bank_id, slot_id). FK: (bank_id, slot_id) -> slot.
 * Row EXISTS <=> slot is provisioned (state 4 / ProvisionedSlotMask bit set).
 *
 * certificate_info follows the rule: STORE REAL, GATE AT READ, WRITER VALIDATES. Multikey is a
 * per-CONNECTION fact, not device state, and one store serves both multikey and non-multikey peers,
 * so the row holds the REAL cert model unconditionally; the multikey gate is applied per read (a
 * non-multikey reader reports CertModel 0 per Table 42, a multikey reader reports the stored value).
 * Storing the gated (0-in-non-multikey) value would be lossy and mode-dependent and could not serve
 * both readers. The WRITER validates the incoming SetCertModel against the WRITING connection's mode
 * (Table 147: non-zero in multikey; the wire forces 0 in non-multikey) but stores it as-is. */
typedef struct {
    uint8_t  bank_id;                     /* [RO] PK part, FK->slot (echoes the array index) */
    uint8_t  slot_id;                     /* [RO] PK part, FK->slot (echoes the array index) */
    bool     present;                     /* [RW] false => no certificate chain (state 2/3) */
    uint8_t  certificate_info;            /* [RW] Table 42 CertificateInfo; stored CertModel in bits
                                           * [2:0] (SPDM_CERTIFICATE_INFO_CERT_MODEL_* 1/2/3); 0 when
                                           * absent. Reported as SlotElement/DIGESTS CertificateInfo
                                           * via the multikey gate (see struct header). */
    size_t   der_size;                    /* [RW] size of the raw chain */
    uint8_t  der[LIBSPDM_DB_CERT_CHAIN_MAX]; /* [RW] raw chain (concatenated DER certs) */
    /* digest is derived on read for the negotiated hash; an optional cache may be added. */
} libspdm_db_cert_chain_t;

/* ---- csr: a GET_CSR transaction -- request inputs AND generated CSR (part C) -----------------
 * A CSR is TRANSIENT peer-driven state, not durable provisioned state: per DSP0274 the Responder
 * "can discard any associated CSR data and reuse the CSRTrackingTag" once the Requester retrieves
 * it. It also has a reset-required flow: if the device requires a reset to complete a GET_CSR, it
 * returns ERROR(ResetRequired) carrying a Responder-assigned CSRTrackingTag, generates the CSR
 * after the reset, and the Requester retrieves it later by that tag. Both halves of the transaction
 * must therefore survive the reset -- the REQUEST inputs (so the CSR can be generated post-reset)
 * and the RETURN value (so it can be retrieved). This is why csr lives in the staging area (part C),
 * not the provisioned info (part B). See "Other ResetRequired flows".
 *
 * Per DSP0274, CSRTrackingTag is a Responder-managed pool of values 1..7 allocated ACROSS the
 * device (not per slot), and the legacy GET_CSR request has no slot address at all. So an entry is
 * keyed by its tracking_tag alone -- NOT by (bank_id, slot_id):
 *   - tracking_tag is the PRIMARY KEY (1..7; 0 is reserved for "new request" and is never stored);
 *   - the CSR identifies its key material by key_pair_id; a CSR is NOT slot-scoped, so no slot_id
 *     is stored, and the bank is the key pair's unique bank (derived from key_pair_id), so no
 *     bank_id is stored either. The SLOT_MANAGEMENT GetCSR SlotAddress carries a (BankID, SlotID),
 *     but the spec has the Responder IGNORE SlotID, and the BankID is only VALIDATED against the
 *     key pair's bank (reject on mismatch), never stored -- storing it would be a second copy that
 *     could drift from key_pair_id.
 *
 * [RO]/[RW] below mark the PK identity ([RO], echoes the array index) vs the per-transaction state
 * the Responder fills in ([RW]). Note this is part C (transient), so [RW] here means "Responder-
 * written transaction state", not the part-B "peer write effective immediately". */
typedef struct {
    bool     present;                     /* [RW] false => this tracking_tag slot is free */
    uint8_t  state;                       /* [RW] LIBSPDM_DB_CSR_STATE_* (FREE/PENDING_RESET/READY) */
    uint8_t  tracking_tag;                /* [RO] PK: responder-assigned CSRTrackingTag, 1..7 */
    /* ---- request half (GET_CSR, Table 98/99) retained to (re)generate the CSR ---- */
    uint8_t  key_pair_id;                 /* [RW] FK->key_pair; the REAL (resolved) key pair, always
                                           * 1..total_key_pairs. The wire Param1 KeyPairID is multikey-
                                           * gated (Table 99: "shall be zero" when !MULTI_KEY_CONN_RSP),
                                           * so in non-multikey it is RESOLVED to the bank's single key
                                           * pair before storing -- never the wire 0 -- so the
                                           * key_pair_id->key_pair cascade matches in both modes. The
                                           * CSR's bank is this key pair's unique bank (derived). */
    uint8_t  request_attributes;          /* [RW] Param2 RequestAttributes (CSRCertModel in [2:0]) */
    size_t   requester_info_len;          /* [RW] Table 98 RequesterInfoLength */
    uint8_t  requester_info[LIBSPDM_DB_REQUESTER_INFO_MAX];  /* [RW] Table 98 RequesterInfo (DER) */
    size_t   opaque_data_len;             /* [RW] Table 98 OpaqueDataLength */
    uint8_t  opaque_data[LIBSPDM_DB_OPAQUE_DATA_MAX];        /* [RW] Table 98 OpaqueData */
    /* ---- return half (CSR response, Table 100); valid only in state READY ---- */
    size_t   der_size;                    /* [RW] */
    uint8_t  der[LIBSPDM_DB_CSR_MAX_SIZE]; /* [RW] the generated CSR */
} libspdm_db_csr_t;

/* ---- db config: the array capacities, so the store is self-descriptive ----------------------
 * These record the LIBSPDM_DB_MAX_* values the arrays in libspdm_db_t were sized with, so a reader
 * of a stored/serialized db knows the dimensions without depending on the build-time macros.
 * All [RO]: this is the part-A header, written once when the store is created and only read after. */
typedef struct {
    uint8_t  db_max_key_pairs;            /* [RO] == LIBSPDM_DB_MAX_KEY_PAIRS */
    uint8_t  db_max_banks;                /* [RO] == LIBSPDM_DB_MAX_BANKS */
    uint8_t  db_max_slots;                /* [RO] == LIBSPDM_DB_MAX_SLOTS */
} libspdm_db_config_t;

/* ---- the device store: the set of "tables" --------------------------------------------------
 * The store is organized in THREE parts, each with a different lifecycle:
 *
 *   A) STRUCTURE INFO  - self-descriptive header (format version + array capacities). Set once when
 *      the store is created and only read thereafter; lets a consumer of a persisted/serialized
 *      store validate the layout before interpreting parts B and C.
 *
 *   B) PROVISIONED INFO - the DURABLE, committed device state that every command READS. It holds
 *      the single authoritative copy of each fact -- the whole point of the model (see Purpose).
 *      All reads come from here (GET_DIGESTS/GET_CERTIFICATE/GET_KEY_PAIR_INFO/SLOT_MANAGEMENT). The
 *      two contiguous dimensions carry a count (total_key_pairs, num_banks); the sparse slot
 *      dimension is represented by per-slot presence (slot[*][*].present) plus the SlotMask
 *      projection. Each part-B member (and each member of the structs it contains) is tagged:
 *        [RO] immutable device fact, set by the Integrator at manufacture; no SPDM command changes
 *             it. These describe the device's structure and capabilities: which key pairs, banks,
 *             and slots exist (total_key_pairs, num_banks, slot[], the key_pair capability fields,
 *             bank_id/bank_attributes).
 *        [RW] mutable provisioned state; a peer write takes effect IMMEDIATELY (the no-reset path of
 *             SET_CERTIFICATE/ManageSlot/SET_KEY_PAIR_INFO/ManageBank) or is promoted from part C on
 *             reset for a reset-required write. The writer is named in the member comment.
 *      key_pair[] and bank[] are MIXED structs: some members are [RO], some [RW] (tagged per member
 *      in their struct definitions above); slot[] is wholly [RO], slot_key_assoc[]/cert_chain[] are
 *      wholly [RW].
 *
 *   C) STAGING AREA - peer-driven state that is NOT (yet) durable part-B state. Two kinds live here:
 *        - reset-deferred shadows (the *_pending fields): when a *_RESET_CAP is advertised, a write
 *          lands HERE instead of part B and does NOT change any read until libspdm_db_apply_pending()
 *          promotes it into part B on the next device reset (so a read in the same boot still returns
 *          the part-B value);
 *        - the CSR transaction (csr[]): a GET_CSR's request inputs and the generated CSR. A CSR is
 *          transient -- the Responder may discard it once retrieved -- and never becomes durable
 *          part-B state, so it lives here regardless of whether its own reset flow is used.
 *      See "Other ResetRequired flows".
 *
 * Splitting B from C is what makes the reset/reload behavior explicit rather than NVM-vs-memory
 * skew: part B is "what is durably served", part C is "pending or transient peer state". */
typedef struct {
    /* ---- A) structure info (write-once header, read-only thereafter; all [RO]) ---- */
    uint8_t                     version;                         /* [RO] == LIBSPDM_DB_FORMAT_VERSION */
    libspdm_db_config_t         config;                          /* [RO] array capacities (see above) */

    /* ---- B) provisioned info (durable committed state; the only thing reads come from) ---- */
    uint8_t                     total_key_pairs;                 /* [RO] Table 111 TotalKeyPairs;
                                                                  * key pairs are key_pair[0..n-1] */
    uint8_t                     num_banks;                       /* [RO] GetBankInfo NumBankElements;
                                                                  * banks are bank[0..num_banks-1] */
    libspdm_db_key_pair_t       key_pair[LIBSPDM_DB_MAX_KEY_PAIRS];     /* [RO]+[RW] mixed (see struct) */
    libspdm_db_bank_t           bank[LIBSPDM_DB_MAX_BANKS];             /* [RO]+[RW] mixed (see struct) */
    libspdm_db_slot_t           slot[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];          /* [RO] */
    libspdm_db_slot_key_assoc_t slot_key_assoc[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];/* [RW] SET_KEY_PAIR_INFO */
    libspdm_db_cert_chain_t     cert_chain[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];    /* [RW] SET_CERTIFICATE/Erase */

    /* ---- C) staging area (pending shadows + transient CSR transactions) ---- */
    /* All [RW], but written into the staging area -- NOT the part-B "effective immediately" sense.
     * Each *_pending field shadows the like-named part-B field, and *_pending_valid says whether a
     * commit of that whole shadow is queued; apply_pending() copies the shadow verbatim on reset.
     * Note cert_chain_pending carries its OWN present flag, so a queued commit covers BOTH a staged
     * install (cert_chain_pending.present == true) and a staged erase (present == false) -- the
     * _valid bit, not the present flag, is what says "a commit is queued". Used only when the
     * corresponding *_RESET_CAP is advertised. */
    libspdm_db_cert_chain_t     cert_chain_pending[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];      /* [RW] */
    bool                        cert_chain_pending_valid[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];/* [RW] */
    libspdm_db_algo_t           bank_algo_pending[LIBSPDM_DB_MAX_BANKS];        /* [RW] ManageBank */
    bool                        bank_algo_pending_valid[LIBSPDM_DB_MAX_BANKS];  /* [RW] */
    libspdm_db_key_pair_t       key_pair_pending[LIBSPDM_DB_MAX_KEY_PAIRS];     /* [RW] SET_KEY_PAIR_INFO */
    bool                        key_pair_pending_valid[LIBSPDM_DB_MAX_KEY_PAIRS];/* [RW] */
    /* CSR transactions: a device-global pool keyed by CSRTrackingTag (1..7), NOT per slot. Index
     * this array by (tracking_tag - 1); tracking_tag is unique because each entry holds a distinct
     * tag. Transient peer state (see libspdm_db_csr_t), not durable part-B provisioned info. */
    libspdm_db_csr_t            csr[LIBSPDM_DB_MAX_CSR];                         /* [RW] (see struct) */
} libspdm_db_t;
```

The `version`/`config` header is initialized to `{ LIBSPDM_DB_FORMAT_VERSION, { LIBSPDM_DB_MAX_KEY_PAIRS,
LIBSPDM_DB_MAX_BANKS, LIBSPDM_DB_MAX_SLOTS } }`; a consumer of a persisted store checks `version`
and `config` before interpreting the arrays.

## The slot state is *derived*, never stored

The four slot states defined in [Slot states](#slot-states) are the **stored** state, computed from
which `libspdm_db_t` array elements are present, so they can never contradict the underlying data.
Each column below is the `present` flag of one array element (all indexed by `[bank_id][slot_id]`):
`present` means the `present` flag is set, `absent` means it is clear.

| State | `slot[bank_id][slot_id]` | `slot_key_assoc[bank_id][slot_id]` | `cert_chain[bank_id][slot_id]` |
| ----- | ------------------------ | ---------------------------------- | ------------------------------ |
| 1. Does not exist | absent | absent | absent |
| 2. Exists and empty | present | absent | absent |
| 3. Exists with key | present | present | absent |
| 4. Exists with key and cert | present | present | present |

This stored state is a device-storage fact, **independent of any connection's multikey mode**. The
key↔slot association (`slot_key_assoc`) exists in storage in both modes and is reported by
`KEY_PAIR_INFO`.`AssocCertSlotMask` (which DSP0274 does not gate on multikey). The combination `slot`
present + `slot_key_assoc` absent + `cert_chain` present is **invalid** — a provisioned slot must
have its key associated — and an implementation should assert/reject it rather than treat it as a
state.

The three arrays are `libspdm_db_t` members of types `libspdm_db_slot_t`,
`libspdm_db_slot_key_assoc_t`, and `libspdm_db_cert_chain_t` (see [Schema](#schema-c-structures)).
The `slot_key_assoc` element is always present in the struct; "present"/"absent" here is its
`present` flag, and `present` carries the associated `key_pair_id` (1..`total_key_pairs`) while
`absent` leaves `key_pair_id` unused (0).

What multikey mode changes is only how the association is **reported in `DIGESTS` and the
`SLOT_MANAGEMENT` `SlotElement`**, not whether it exists: `DIGESTS.KeyPairID[X]` and
`SlotElement.KeyPairID` are present/populated only when `MULTI_KEY_CONN_REQ`/`RSP` is true and are
otherwise forced to 0 (DSP0274 Tables 41, 152); likewise the `ProvisionedSlotMask` "associated key"
clause is multikey-only. So in a non-multikey connection a state-3 slot (key, no cert) is still
visible via `KEY_PAIR_INFO`.`AssocCertSlotMask`, but `DIGESTS` reports it with `Provisioned = 0`
(indistinguishable from state 2 in the `DIGESTS` view).

Because every view is a query over the same structures, a single write propagates everywhere at
once. The exhaustive field-by-field mapping is below.

## Mapping wire structures to the schema

Every field of every SLOT_MANAGEMENT / KEY_PAIR_INFO / DIGESTS wire structure is listed, with the
schema source it is read from or written to. `bank_id`, `slot_id`, and `key_pair_id` are the
addressed Bank, Slot, and KeyPair; "bit N" of a mask is the bit for slot N. "derived (connection)"
means the value depends on the negotiated algorithm/hash of the current connection, not on stored
device state.

### BankInfo (Table 149 — GetBankInfo)

| Wire field | Schema source |
| ---------- | ------------- |
| `RespLength` | structural (computed from `NumBankElements`) |
| `NumBankElements` | `num_banks` |
| `BankElements[]` | one `BankElement` per `bank[0..num_banks-1]` (see below) |

### BankElement (Table 150 — within BankInfo)

| Wire field | Schema source |
| ---------- | ------------- |
| `ElementLength` | constant (4); structural |
| `BankID` | `bank[bank_id].bank_id` |
| `SlotMask` | bit slot_id set ⇔ `slot[bank_id][slot_id].present` (slot exists) |
| `ModifiableSlotMask` | bit slot_id set ⇔ `slot[bank_id][slot_id].present && slot[bank_id][slot_id].modifiable` (and, per spec, the `SlotMask` bit is set) |

### BankDetails (Table 151 — GetBankDetails)

| Wire field | Schema source |
| ---------- | ------------- |
| `RespLength` | structural (computed from `NumSlotElements`) |
| `BankID` | `bank[bank_id].bank_id` |
| `NumSlotElements` | count of `slot[bank_id][*].present` |
| `BankAttributes` | `bank[bank_id].bank_attributes` with the derived `SELECTED` bit OR'd in: `SELECTED` ⇔ `bank[bank_id].algo == negotiated algo`; `CONFIG_ALGO` from the stored byte |
| `AsymAlgoCapabilities` | `bank[bank_id].asym_algo_capabilities` (the bank's stored capability fact, captured from its key pair(s); 0 if `CONFIG_ALGO` clear in `bank[bank_id].bank_attributes`) |
| `CurrentAsymAlgo` | `bank[bank_id].algo.asym_algo` |
| `AvailableAsymAlgo` | `AsymAlgoCapabilities` minus algorithms already assigned to another bank (`bank[*].algo`) |
| `PqcAsymAlgoCapLen` / `PqcAsymAlgoCapabilities` | length is constant (4); value is `bank[bank_id].pqc_asym_algo_capabilities` (0 if `CONFIG_ALGO` clear in `bank[bank_id].bank_attributes`) |
| `CurrentPqcAsymAlgoLen` / `CurrentPqcAsymAlgo` | length is constant (4); value is `bank[bank_id].algo.pqc_asym_algo` |
| `AvailablePqcAsymAlgoLen` / `AvailablePqcAsymAlgo` | length is constant (4); value is `PqcAsymAlgoCapabilities` minus PQC algorithms already assigned to another bank (`bank[*].algo.pqc_asym_algo`) |
| `SlotElements[]` | one entry per `slot[bank_id][slot_id].present` (see below) |

### SlotElement (Table 152 — within BankDetails)

| Wire field | Schema source |
| ---------- | ------------- |
| `ElementLength` | constant (16 + H); structural |
| `SlotID` | `slot[bank_id][slot_id].slot_id` |
| `SlotAttributes` | `slot[bank_id][slot_id].slot_attributes` with the derived `PROVISIONED` bit OR'd in: `PROVISIONED` ⇔ `cert_chain[bank_id][slot_id].present`; `WRITE_PROTECTED` from the stored byte |
| `KeyPairID` | `slot_key_assoc[bank_id][slot_id].key_pair_id` (0 if `!MULTI_KEY_CONN_RSP` or no assoc) |
| `CertificateInfo` | `cert_chain[bank_id][slot_id].certificate_info` (0 if no cert; also 0 when `!MULTI_KEY_CONN_RSP` — per Table 42 `CertModel` is 0 in a non-multikey connection regardless of the stored cert) |
| `KeyUsage` | derived: if `slot_key_assoc[bank_id][slot_id].present`, then `key_pair[slot_key_assoc[bank_id][slot_id].key_pair_id - 1].current_key_usage` (key_pair_id is 1-based, so it is non-zero here); otherwise 0 (no associated key pair) |
| `SlotSize` | capacity for `cert_chain[bank_id][slot_id].der` (device/store constant) |
| `Digest` | derived (connection): hash of `cert_chain[bank_id][slot_id].der` under the negotiated hash; all-zero if not provisioned |

### GetCertificateChain structure (Table 153 — GetCertificateChain)

| Wire field | Schema source |
| ---------- | ------------- |
| `CCLength` | `cert_chain[bank_id][slot_id].der_size` (+ Table 39 header/root-hash, assembled on read) |
| `CertChain` | `cert_chain[bank_id][slot_id].der` assembled into the Table 39 chain (header + root hash + DER) |

### SupportedSubCodes (Table 148 — SupportedSubCodes)

| Wire field | Schema source |
| ---------- | ------------- |
| `RespLength` | constant (36); structural |
| `SubCodeBitmap` | device capability constant (not in these tables; the supported-SubCode set) |

### KEY_PAIR_INFO response (Table 111 — GET_KEY_PAIR_INFO)

The `GET_KEY_PAIR_INFO` request's `KeyPairID` is **not** multikey-gated — per Table 110 it is the real
key pair number in both modes, valid range `1..total_key_pairs` (0 is invalid: it means "no key
pair"). A request with `KeyPairID` outside that range is an `InvalidRequest` and is rejected before
any lookup, so the `key_pair[key_pair_id - 1]` indexing below is always reached with `key_pair_id >= 1`
(never an underflow). See [the indexing convention](#schema-c-structures) ("Index this array by
`(key_pair_id - 1)` ONLY after checking `key_pair_id != 0`").

| Wire field | Schema source |
| ---------- | ------------- |
| `TotalKeyPairs` | `total_key_pairs` |
| `KeyPairID` | `key_pair[key_pair_id - 1].key_pair_id` |
| `Capabilities` | `key_pair[key_pair_id - 1].capabilities` (Table 112 bits) |
| `KeyUsageCapabilities` | `key_pair[key_pair_id - 1].key_usage_capabilities` |
| `CurrentKeyUsage` | `key_pair[key_pair_id - 1].current_key_usage` |
| `AsymAlgoCapabilities` | `key_pair[key_pair_id - 1].asym_algo_capabilities` |
| `CurrentAsymAlgo` | `key_pair[key_pair_id - 1].current_asym_algo` |
| `PublicKeyInfoLen` | `key_pair[key_pair_id - 1].public_key_info_len` (0 ⇒ key absent/ungenerated) |
| `AssocCertSlotMask` | **derived**: bit slot_id set ⇔ `slot_key_assoc[bank_id][slot_id].key_pair_id == key_pair_id`, where bank_id is the unique bank whose `algo` equals this key pair's current algorithm (see the key_pair "maps to at most one bank" invariant; all-zero for an unconfigured key pair, which has no associations). Not stored — the inverse of `slot_key_assoc` |
| `PublicKeyInfo` | `key_pair[key_pair_id - 1].public_key_info` |
| `PqcAsymAlgoCapLen` / `PqcAsymAlgoCapabilities` | length is constant (4); value is `key_pair[key_pair_id - 1].pqc_asym_algo_capabilities` |
| `CurrentPqcAsymAlgoLen` / `CurrentPqcAsymAlgo` | length is constant (4); value is `key_pair[key_pair_id - 1].current_pqc_asym_algo` |

### GET_DIGESTS / DIGESTS (Table for digests)

| Wire field | Schema source |
| ---------- | ------------- |
| `SupportedSlotMask` (Param1) | bit slot_id ⇔ `slot[bank_id][slot_id].present`, bank_id = selected bank |
| `ProvisionedSlotMask` (Param2) | bit slot_id ⇔ `cert_chain[bank_id][slot_id].present` **OR** ((`MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP`) and `slot_key_assoc[bank_id][slot_id].present`), bank_id = selected bank |
| `Digest[slot_id]` | derived (connection): hash of `cert_chain[bank_id][slot_id].der`; all-zero if not provisioned |
| `KeyPairID[slot_id]` | `slot_key_assoc[bank_id][slot_id].key_pair_id` |
| `CertificateInfo[slot_id]` | `cert_chain[bank_id][slot_id].certificate_info`; present only when `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` (Table 41) — absent otherwise, and per Table 42 its `CertModel` would be 0 in a non-multikey connection regardless |
| `KeyUsageMask[slot_id]` | derived: if `slot_key_assoc[bank_id][slot_id].present`, then `key_pair[slot_key_assoc[bank_id][slot_id].key_pair_id - 1].current_key_usage` (key_pair_id is non-zero here); otherwise 0 (no associated key pair) |

> NOTE: Per DSP0274 Table 41 the spec qualifies both `ProvisionedSlotMask` terms with "supports the
> currently negotiated algorithms"; that qualifier is automatically met here because the reported
> bank is the one *selected by* the negotiated algorithm, so every cert/key in it matches by
> construction. So in multikey mode a slot with an associated key pair (state 3) is also reported
> provisioned — unlike `SlotElement.SlotAttributes.Provisioned`, which is cert-only ("set to 1 if the
> slot contains a certificate chain", Table 152).

### GET_CERTIFICATE / CERTIFICATE (selected bank)

| Wire field | Schema source |
| ---------- | ------------- |
| `CertChain` (for slot `slot_id`) | `cert_chain[bank_id][slot_id].der` assembled into the Table 39 chain, bank_id = selected bank; `ERROR(InvalidRequest)` if `!cert_chain[bank_id][slot_id].present` |

### CHALLENGE / CHALLENGE_AUTH (selected bank)

| Wire field | Schema source |
| ---------- | ------------- |
| `Param2` (slot mask) | bit slot_id ⇔ `cert_chain[bank_id][slot_id].present`, bank_id = selected bank. Per DSP0274 Table 51 this bit is set only for the "Exists with key and cert" state (state 4) — i.e. the slot has a key provisioned **and** a certificate chain; it is reserved if the Responder's public key was provisioned to the Requester in a trusted environment. Unlike `DIGESTS.ProvisionedSlotMask`, it is not multikey-gated and never reflects a key-only (state 3) slot |

### Write requests (which structure each command writes)

An asset may be updatable by **more than one path** (e.g. `cert_chain` via the legacy `SET_CERTIFICATE`
*or* the `SLOT_MANAGEMENT SetCertificate` SubCode). Each path is listed as its own row and is gated
**only by its own path capability** — the legacy and `SLOT_MANAGEMENT` capabilities are independent
and are never AND-ed together. The gate column combines two kinds of condition:

* **Path capability** — gates this path only: `CAPABILITIES.Flags.*` for a legacy message, or
  `CAPABILITIES.ExtFlags.SLOT_MGMT_CAP == 1 && SLOT_MANAGEMENT.SupportedSubCodes.SubCodeBitmap[<value>] == 1`
  for a `SLOT_MANAGEMENT` SubCode (bit position = SubCode value).
* **Per-asset device gate** — a device fact about the target asset (slot attribute, key-pair
  capability, bank attribute) that applies on **any** path that reaches the asset.

| Asset | Request (path) | Path capability | Per-asset device gate | Effect on the schema |
| ----- | -------------- | --------------- | --------------------- | -------------------- |
| `cert_chain` (slot) | `SET_CERTIFICATE` (legacy, Table 147) | `CAPABILITIES.Flags.SET_CERT_CAP == 1` | `SLOT_MANAGEMENT.BankDetails.SlotElement.SlotAttributes.WRITE_PROTECTED == 0` && `SLOT_MANAGEMENT.BankInfo.BankElement.ModifiableSlotMask[slot_id] == 1` | write `cert_chain[bank_id][slot_id]` (`der`, `certificate_info`), state 3 → 4. Requires the slot **already associated** with the request's `KeyPairID`, matching bank algorithm, and matching leaf public key (install ASSUMPTION 1/2/3 above); does **not** create `slot`/`slot_key_assoc` |
| `cert_chain` (slot) | `SLOT_MANAGEMENT SetCertificate` (Table 147) | `CAPABILITIES.ExtFlags.SLOT_MGMT_CAP == 1` && `SLOT_MANAGEMENT.SupportedSubCodes.SubCodeBitmap[0x22] == 1` | `SLOT_MANAGEMENT.BankDetails.SlotElement.SlotAttributes.WRITE_PROTECTED == 0` && `SLOT_MANAGEMENT.BankInfo.BankElement.ModifiableSlotMask[slot_id] == 1` | write `cert_chain[bank_id][slot_id]` (`der`, `certificate_info`), state 3 → 4. Requires the slot **already associated** with the request's `KeyPairID`, matching bank algorithm, and matching leaf public key (install ASSUMPTION 1/2/3 above); does **not** create `slot`/`slot_key_assoc` |
| `cert_chain` (slot) | `SET_CERTIFICATE` `Erase` (legacy) | `CAPABILITIES.Flags.SET_CERT_CAP == 1` | `SLOT_MANAGEMENT.BankDetails.SlotElement.SlotAttributes.WRITE_PROTECTED == 0` && `SLOT_MANAGEMENT.BankInfo.BankElement.ModifiableSlotMask[slot_id] == 1` | no reset required: clear `cert_chain[bank_id][slot_id].present` now; **keep** `slot_key_assoc[bank_id][slot_id]`. If `CERT_INSTALL_RESET_CAP` requires a reset: **stage the erase** — set a `cert_chain_pending[bank_id][slot_id]` row with `present == false` and `cert_chain_pending_valid[bank_id][slot_id]`, leaving the committed chain live until `libspdm_db_apply_pending()` copies that row (clearing the cert) on reset. Either way **supersedes any reset-required commit already staged for the slot** in `cert_chain_pending`, so a later reset cannot re-commit the erased certificate |
| `cert_chain` (slot) | `SLOT_MANAGEMENT ManageSlot` `Erase` (Table 146) | `CAPABILITIES.ExtFlags.SLOT_MGMT_CAP == 1` && `SLOT_MANAGEMENT.SupportedSubCodes.SubCodeBitmap[0x21] == 1` | `SLOT_MANAGEMENT.BankDetails.SlotElement.SlotAttributes.WRITE_PROTECTED == 0` && `SLOT_MANAGEMENT.BankInfo.BankElement.ModifiableSlotMask[slot_id] == 1` | no reset required: clear `cert_chain[bank_id][slot_id].present` now; **keep** `slot_key_assoc[bank_id][slot_id]`. If `CERT_INSTALL_RESET_CAP` requires a reset: **stage the erase** — set a `cert_chain_pending[bank_id][slot_id]` row with `present == false` and `cert_chain_pending_valid[bank_id][slot_id]`, leaving the committed chain live until `libspdm_db_apply_pending()` copies that row (clearing the cert) on reset. Either way **supersedes any reset-required commit already staged for the slot** in `cert_chain_pending`, so a later reset cannot re-commit the erased certificate |
| `key_pair` | `SET_KEY_PAIR_INFO` `GenerateKeyPair` | `CAPABILITIES.Flags.SET_KEY_PAIR_INFO_CAP == 1` | `KEY_PAIR_INFO.Capabilities.GenKeyCap == 1` | set `key_pair[key_pair_id - 1].public_key_info*`, `current_*`; (association via a separate change). Also **discards any `csr` for this key pair** (incl. a `PENDING_RESET` tag): the new key invalidates a CSR built for the old material (`csr.key_pair_id` → `key_pair` cascade) |
| `key_pair` | `SET_KEY_PAIR_INFO` `KeyPairErase` | `CAPABILITIES.Flags.SET_KEY_PAIR_INFO_CAP == 1` | `KEY_PAIR_INFO.Capabilities.ErasableCap == 1` | clear `key_pair[key_pair_id - 1]` key material; allowed only if no `slot_key_assoc` references it. Also **discards any `csr` for this key pair** (incl. a `PENDING_RESET` tag): the erased key invalidates its CSR (`csr.key_pair_id` → `key_pair` cascade) |
| `slot_key_assoc` + `key_pair` | `SET_KEY_PAIR_INFO` (associate / dissociate / set usage / set algo) | `CAPABILITIES.Flags.SET_KEY_PAIR_INFO_CAP == 1` | one of:<br>• associate/dissociate: `KEY_PAIR_INFO.Capabilities.CertAssocCap == 1` (+ `KEY_PAIR_INFO.Capabilities.ShareableCap == 1` for cardinality > 1)<br>• set-usage: `KEY_PAIR_INFO.Capabilities.KeyUsageCap == 1`<br>• set-algo: `KEY_PAIR_INFO.Capabilities.AsymAlgoCap == 1` | Set/clear `slot_key_assoc[bank_id][slot_id].key_pair_id` and/or `key_pair[key_pair_id - 1].current_key_usage` / `current_*_algo`. Key usage is set on the key pair, never per slot. **Dissociate** (clearing `slot_key_assoc[bank_id][slot_id]`, a `DesiredAssocCertSlotMask` bit cleared) additionally **discards any reset-required certificate staged for that slot** in `cert_chain_pending` (it was queued under the association, so it must not commit onto an unassociated slot at reset); a dissociate is rejected if a committed `cert_chain` is still present (Erase it first). |
| `bank` (+ its slots) | `SLOT_MANAGEMENT ManageBank` `ConfigAlgo` (Table 145) | `CAPABILITIES.ExtFlags.SLOT_MGMT_CAP == 1` && `SLOT_MANAGEMENT.SupportedSubCodes.SubCodeBitmap[0x20] == 1` | `SLOT_MANAGEMENT.BankDetails.BankAttributes.CONFIG_ALGO == 1` | allowed only if no slot in the bank has an **associated key pair** — i.e. no slot is in state 3 or state 4 (else `InvalidState`, DSP0274 Table 141). Only states 1/2 are permitted; a state-3/4 slot must be dissociated (and its cert erased) via `SET_KEY_PAIR_INFO`/`Erase` **first**, so `ConfigAlgo` never implicitly drops an association or changes any key pair's `AssocCertSlotMask`. Set `bank[bank_id].algo` **and clear all slot settings** in that bank (DSP0274: "When the Bank configuration changes, the Responder shall clear all slot settings"); with only states 1/2 present there is no `slot_key_assoc`/`cert_chain` row to drop, and a dissociate has already discarded each slot's `cert_chain_pending`, so this clears only any residual `slot` attributes (the `cert_chain_pending` clear is defensive). The `csr` pool is **not** touched: a `csr` stores no `bank_id`/`slot_id` and `ConfigAlgo` erases no key pair. An all-zero `SelectAsymAlgo`/`SelectPqcAsymAlgo` (zero algorithm bits) is rejected with `InvalidRequest` — `ConfigAlgo` must select exactly one algorithm. The selected algorithm shall be in the bank's `AvailableAsymAlgo`/`AvailablePqcAsymAlgo` — i.e. supported by the bank (in its `AsymAlgoCapabilities`) **and** not already configured for another bank — else `InvalidRequest` (DSP0274 Table 145: "the set bit shall match one of the algorithms ... in the `AsymAlgoCapabilities` field" and "another Bank is already configured for the given algorithm"). The responder lib enforces this membership using the same Available value `GetBankDetails` reports; it preserves the one-bank-per-algorithm uniqueness invariant |
| `csr` | `GET_CSR` (legacy, Table 144) | `CAPABILITIES.Flags.CSR_CAP == 1` | — | allocate a free `CSRTrackingTag` (1..7) and fill that `csr[tag-1]` entry with the request inputs (`key_pair_id`, `request_attributes`, `requester_info`, `opaque_data`); no `bank_id`/`slot_id` is stored (a CSR is not slot-scoped). The wire `KeyPairID` is multikey-gated (Table 99: "shall be zero" when `!MULTI_KEY_CONN_RSP`), so in non-multikey it is **resolved** to the bank's single key pair and that **real** id is stored in `key_pair_id` — never the wire 0 — so the `key_pair_id` → `key_pair` cascade matches in both modes. Reset flow: if a reset is required, set `state = PENDING_RESET` and return `ResetRequired` with the tag (`der` generated, `state = READY` after reset); else generate `der` immediately. Freed once the Requester retrieves the CSR |
| `csr` | `SLOT_MANAGEMENT GetCSR` (Table 144) | `CAPABILITIES.ExtFlags.SLOT_MGMT_CAP == 1` && `SLOT_MANAGEMENT.SupportedSubCodes.SubCodeBitmap[0x04] == 1` | — | as the legacy `GET_CSR` row (same wire-`KeyPairID` resolution and stored real `key_pair_id`); the request's `BankID` is **validated** against the key pair's bank (reject on mismatch) but not stored, and `SlotID` is ignored (Table 143) |

A write is accepted only if **both** its path capability and its per-asset device gate hold
(`UnsupportedRequest` if the path capability is absent; `InvalidRequest`/`InvalidState` otherwise).
Because the two paths to one asset carry independent capabilities, disabling one path (e.g. clearing
`SET_CERT_CAP`) does not disable the other (`SLOT_MANAGEMENT SetCertificate`), and vice versa.

#### State preconditions (beyond the capability gates)

Capabilities say a write is *allowed*; these **ordering/state preconditions** say it is *valid right
now*, given what the asset currently holds. They are enforced in addition to the gates above, and a
violation is rejected with the listed `ErrorCode`. They come from DSP0274 §"Key pair ID modification
error handling" and §"SLOT_MANAGEMENT" (Table 141).

| Operation | Precondition (must hold) | Schema test | Error if violated |
| --------- | ------------------------ | ----------- | ----------------- |
| `SET_KEY_PAIR_INFO` `GenerateKeyPair` | an asymmetric algorithm is already selected for the key pair (generate is bound to `CurrentAsymAlgo`/`CurrentPqcAsymAlgo`) | `key_pair[id-1].current_asym_algo != 0 \|\| current_pqc_asym_algo != 0` | `OperationFailed` |
| `SET_KEY_PAIR_INFO` `GenerateKeyPair` | the key pair is **not associated with any certificate slot** | for all banks: `libspdm_db_assoc_cert_slot_mask(db, bank, id) == 0` | `OperationFailed` |
| `SET_KEY_PAIR_INFO` `KeyPairErase` | the key pair is **not associated with any certificate slot** (erase the certificate chains first) | for all banks: `libspdm_db_assoc_cert_slot_mask(db, bank, id) == 0` | `OperationFailed` |
| `SET_KEY_PAIR_INFO` `ParameterChange` (set algo) | the asymmetric algorithm is **not changed once a key pair has been generated** (the key is bound to the algorithm) | reject a different `DesiredAsymAlgo`/`DesiredPqcAsymAlgo` when `public_key_info_len != 0` (a key exists) | discard or `InvalidRequest` |
| `SET_KEY_PAIR_INFO` `ParameterChange` (associate) | a slot may be associated only with a key pair whose algorithm matches the slot's **bank algorithm** (algorithm-agreement) | `key_pair[id-1].current_*_algo == bank[bank_id].algo` | `InvalidRequest` |
| `SET_CERTIFICATE` / `SetCertificate` (install) | the slot is **already associated** with the request's `KeyPairID`, that key pair's **algorithm matches** the bank, and the chain's **leaf public key matches** that key pair's `public_key_info` (a cert is verifiable under exactly one key/algorithm). See the assumption note below — this model does **not** let `SET_CERTIFICATE` create or change the association | `slot_key_assoc[bank][slot].present == 1` && `slot_key_assoc[bank][slot].key_pair_id == KeyPairID` && `key_pair[KeyPairID-1].current_*_algo == bank[bank].algo` && `leaf_pubkey(chain) == key_pair[KeyPairID-1].public_key_info` | `InvalidRequest` |
| `ManageBank` `ConfigAlgo` | **no slot in the bank has an associated key pair** (no slot in state 3 **or** state 4); only states 1/2 are allowed. A state-3 slot (key, no cert) must first be dissociated via `SET_KEY_PAIR_INFO`, and a state-4 slot's cert erased then dissociated, before `ConfigAlgo` — so `ConfigAlgo` never implicitly drops an association | for all slots in bank: `slot_key_assoc[bank][slot].present == 0` | `InvalidState` |
| `ManageBank` `ConfigAlgo` | exactly one algorithm bit is selected (all-zero is rejected) | `popcount(SelectAsymAlgo) + popcount(SelectPqcAsymAlgo) == 1` | `InvalidRequest` |
| `ManageBank` `ConfigAlgo` | the selected algorithm is one the bank **supports** (DSP0274 Table 145: "the set bit shall match one of the algorithms ... in the `AsymAlgoCapabilities` field of the `BankDetails` response") | `selected_algo ⊆ bank[bank_id].{asym,pqc_asym}_algo_capabilities` | `InvalidRequest` |
| `ManageBank` `ConfigAlgo` | the selected algorithm is **not already configured for another bank** (CurrentAlgo is unique across configured banks; see the `bank` uniqueness invariant and DSP0274 Table 145 ConfigAlgo: "another Bank is already configured for the given algorithm") | for all banks `other != bank_id`: `bank[other].algo != selected_algo` | `InvalidRequest` |
| `ManageBank` `ConfigAlgo` | *(the two rows above together are exactly: `selected_algo ⊆ bank[bank_id].AvailableAsymAlgo`/`AvailablePqcAsymAlgo`, which the responder lib checks via the GetBankDetails HAL)* | `selected_algo ⊆ available_*` | `InvalidRequest` |

> NOTE: the "no association" precondition for `GenerateKeyPair`/`KeyPairErase` is the inverse of the
> normal provisioning order: a key pair must be **dissociated from every slot** (which in turn
> requires the slots' certificate chains to be erased first) before its key material can be generated
> or erased. This is why returning a key pair to default values is "erase certs → dissociate → erase
> key", and provisioning is the reverse.

> ASSUMPTION (`SET_CERTIFICATE` / `SetCertificate` install). DSP0274 frames the request's `KeyPairID`
> as "the desired asymmetric key pair **to associate with** `SlotID`" (Table 101 `Param2`; Table 147
> `KeyPairID`), and the only "match" it explicitly mandates is between the **certificate chain and
> that `KeyPairID`/model**: "the Responder should verify that contents of the certificate chain meet
> the requirements … for the requested certificate model **and key pair** … if it does not, the
> Responder shall retain the current certificate" (§"SET_CERTIFICATE", Table 101 notes). A literal
> reading therefore lets `SET_CERTIFICATE` **create or re-point** the association from its own
> `KeyPairID` as part of the install (state 2 → 4), with no requirement that the slot be associated
> first and no concept of a "mismatch with a previously-associated `KeyPairID`" — under that reading
> the request *is* the association authority.
>
> **This model takes the stricter reading:** a `SET_CERTIFICATE` install requires the slot to be
> **already associated** (`SET_KEY_PAIR_INFO` first), and the request's `KeyPairID` must **equal** the
> existing association — `SET_CERTIFICATE` never creates or changes it. On top of that the model
> enforces all three of:
> 1. **assoc == 1** — `slot_key_assoc[bank][slot].present` and `key_pair_id == KeyPairID`. The wire
>    `KeyPairID` is multikey-gated (Table 101/147: "shall be zero" when `!MULTI_KEY_CONN_RSP`), so in
>    non-multikey mode it is resolved to the slot's single implicit key pair (its existing
>    association) before this check;
> 2. **algo is same** — the associated key pair's current algorithm equals the bank algorithm
>    (the same algorithm-agreement check `libspdm_db_associate_slot_key()` applies); and
> 3. **pubkey content is same** — the installed chain's leaf public key equals the associated key
>    pair's `public_key_info` (the chain-↔-key-pair match DSP0274 actually requires).
>
> A failure of (1) or (2) is `InvalidRequest`; a failure of (3) is the Table 101 verification failure
> (reject and **retain** any existing certificate). A Responder taking the literal reading (associate
> via `Param2` during install) would also conform to DSP0274; this stricter precondition is recorded
> as [open spec question](#open-spec-questions) #6, pending a spec clarification.

Because every read field above resolves to exactly one schema location, and every write updates that
one location, a single write is immediately visible to **all** of the reads — there is no second
copy to update.

## Integrity constraints that resolve the gaps

The gaps are eliminated by declarative constraints rather than by hoping each command writer keeps
the copies in sync.

### Gap #3638 — key-pair ↔ slot association consistency

Root cause: three independent arrays (`AssocCertSlotMask`, per-slot `KeyPairID` in `GET_DIGESTS`,
and the per-slot certificate's algorithm) are written separately and drift.

Resolution: there is exactly **one** association fact — a row in `slot_key_assoc`. All three views
are queries over it, so:

* `GET_DIGESTS.KeyPairID[slot_id]` ≡ `GetBankDetails.SlotElement(slot_id).KeyPairID` ≡ the
  `key_pair_id` in `slot_key_assoc` for `(bank_id, slot_id)` — identical by construction.
* `AssocCertSlotMask(key_pair_id)` is the inverse projection of the same rows, so
  "`KeyPairID[slot_id]` equals the key pair whose `AssocCertSlotMask` has bit `slot_id` set" holds automatically.

Plus an algorithm-agreement constraint so the slot's certificate matches its key pair's algorithm,
and the key pair's algorithm matches the bank's. These checks live in `libspdm_db_associate_slot_key()`
(see [Access API implementations](#access-api-implementations)): an association whose key-pair
algorithm differs from the bank's is rejected, so a slot's certificate is always verifiable under the
single algorithm reached through `slot_key_assoc` → `key_pair` — there is no second algorithm copy
that could disagree.

### Gap #3645 — the "exists with key" state must be reachable

Root cause: there was no representation of "key present, no cert", so `GenerateKeyPair` /
`KeyPairErase` had no slot-level effect and the state was unreachable.

Resolution: state 3 is simply a `slot` row + a `slot_key_assoc` row + **no** `cert_chain` row, which
the model represents natively. The transitions become ordinary row operations:

* `GenerateKeyPair` for a key pair, then associate it to a slot → `INSERT slot_key_assoc` → state 2→3.
* `SetCertificate` → `INSERT cert_chain` → state 3→4 (the slot must already be associated; the
  install does not create the assoc — see the install ASSUMPTION).
* `Erase` (ManageSlot / SET_CERTIFICATE) → `DELETE cert_chain`, **keep** `slot_key_assoc` → 4→3.
* `KeyPairErase` → `DELETE slot_key_assoc` (allowed only when no `cert_chain` row) → 3→2.

The "Erase keeps the key" rule (DSP0274 §3115) is expressed exactly: Erase deletes only the
`cert_chain` row, never the `slot_key_assoc` row.

## Single store and reset semantics

This section is not about resolving a gap — it describes how the one normalized store behaves for
writes and the `ResetRequired` two-phase commit.

### One write, one served value (no reset/reload divergence)

The relational model is single-source-of-truth: `GET_CERTIFICATE`, `CHALLENGE`, `KEY_EXCHANGE`, and
the `SLOT_MANAGEMENT` reads all read the **same** `cert_chain[bank_id][slot_id]` row. A
`SET_CERTIFICATE` is a single write to that row (or a clear of `present` for erase); every reader
sees it immediately. The `CERT_INSTALL_RESET_CAP` / `ResetRequired` flow is an explicit two-phase
commit modeled by the `cert_chain_pending` rows in `libspdm_db_t`, not a divergence:

* If `CERT_INSTALL_RESET_CAP` is **not** advertised, `SET_CERTIFICATE` commits directly to
  `cert_chain[bank_id][slot_id]` and is effective live.
* If it **is** advertised, the write lands in `cert_chain_pending[bank_id][slot_id]`, the Responder returns
  `ResetRequired`, and the reset handler applies `cert_chain_pending` → `cert_chain` atomically. A
  read in the same boot still reflects the committed (pre-pending) chain, and the pending state is
  explicit rather than implied by NVM-vs-memory skew.

An `Erase` follows the same two-phase pattern, and uses the **same** shadow as install: install and
erase both stage a desired `cert_chain` row in `cert_chain_pending[bank_id][slot_id]` and set
`cert_chain_pending_valid[bank_id][slot_id]`; they differ only in that row's `present` flag (install
stages `present = true` + DER, erase stages `present = false`). With no reset required the change is
applied to `cert_chain` live; when a reset is required it is staged (leaving the committed chain
readable until reset), and `libspdm_db_apply_pending()` copies the shadow row — `present` flag and
all — onto `cert_chain`. Because a slot has at most one queued commit, a reset can never both install
and erase the same slot.

For the AliasCert model, chain assembly (appending the slot-0 Alias cert to form a complete chain)
is a read-time assembly over `cert_chain`, deterministic from the same store.

### Other ResetRequired flows

`ResetRequired` is not specific to certificate install. DSP0274 also allows it for:

* **`ManageBank` `ConfigAlgo`** — "If a Responder requires a reset before a reconfigured Bank can be
  used … `ResetRequired`" (Table 141).
* **`SET_KEY_PAIR_INFO`** when `SET_KEY_PAIR_RESET_CAP` is advertised.

The same two-phase pattern applies: the write lands in a pending field, the Responder returns
`ResetRequired`, and the reset handler (`libspdm_db_apply_pending()`) commits it. The store therefore
carries a pending shadow for each reset-capable write, not just certificates:

```c
/* pending (reset-required) shadows, all committed by libspdm_db_apply_pending(): each is a shadow
 * value plus a _valid flag, and apply_pending() copies the shadow onto the live field when valid. */
libspdm_db_cert_chain_t  cert_chain_pending[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];
bool                     cert_chain_pending_valid[LIBSPDM_DB_MAX_BANKS][LIBSPDM_DB_MAX_SLOTS];
libspdm_db_algo_t        bank_algo_pending[LIBSPDM_DB_MAX_BANKS];      /* ManageBank ConfigAlgo */
bool                     bank_algo_pending_valid[LIBSPDM_DB_MAX_BANKS];
libspdm_db_key_pair_t    key_pair_pending[LIBSPDM_DB_MAX_KEY_PAIRS];   /* SET_KEY_PAIR_INFO */
bool                     key_pair_pending_valid[LIBSPDM_DB_MAX_KEY_PAIRS];
```

When the corresponding `*_RESET_CAP` is not advertised, each write commits directly and these
pending shadows are unused.

## Worked propagation example

`SET_CERTIFICATE(bank=0, slot=1, chain C, model=DeviceCert)` with no reset required:

```c
/* the slot must ALREADY be associated to key pair K (state 3) via libspdm_db_associate_slot_key();
 * SET_CERTIFICATE does not create the association. The install then checks assoc==K, algo match, and
 * leaf-pubkey match before writing the chain (state 3 -> 4). multi_key is MULTI_KEY_CONN_RSP; here it
 * is true, so the wire KeyPairID is K. (In non-multikey, multi_key=false and the wire KeyPairID is 0,
 * which resolves to the slot's implicit key pair.) */
libspdm_db_set_certificate(db, /*bank*/ 0, /*slot*/ 1, /*multi_key*/ true, /*key_pair_id*/ K,
                           SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT, C, C_size,
                           leaf_pubkey_of_C, leaf_pubkey_of_C_len, /*reset_required*/ false);
```

Immediately afterwards, **without any extra code in the other command handlers**:

* `GET_CERTIFICATE(slot=1)` (if bank 0 is the selected bank) returns `C` — reads `cert_chain[0][1]`.
* `GET_DIGESTS` reports `ProvisionedSlotMask` bit 1 set and a digest of `C`.
* `SLOT_MANAGEMENT GetBankDetails(bank=0)` reports slot 1 as `Provisioned=1`,
  `CertificateInfo=DeviceCert`, `KeyPairID` = `slot_key_assoc[0][1].key_pair_id`.
* `GET_KEY_PAIR_INFO` for that key pair shows bit 1 set in `AssocCertSlotMask` (inverse of
  `slot_key_assoc`).

A subsequent `ManageSlot Erase(bank=0, slot=1)` is `db->cert_chain[0][1].present = false;` — every
view drops to "exists with key" (state 3) at once, and the key pair association (`slot_key_assoc`,
hence the `AssocCertSlotMask` bit) is retained.

## Access API

The structures are mutated only through a small set of access functions, so the invariants live in
one place. Reads compose the wire structures from the tables; writes touch exactly one row.

**Referential cascades.** The FKs (`slot_key_assoc`/`cert_chain` → `slot`, `slot` → `bank`,
`csr.key_pair_id` → `key_pair`) imply `ON DELETE CASCADE`: clearing a `slot` row clears its
`slot_key_assoc` and `cert_chain`; reconfiguring/removing a `bank` clears all of its slots' rows
(this is also the ManageBank "clear all slot settings" cascade). A `csr` is **not** a child of a
`slot` or `bank` — it is keyed by `CSRTrackingTag` and stores no `bank_id`/`slot_id`, so neither
clearing a slot nor reconfiguring a bank touches it (`ManageBank ConfigAlgo` changes the bank
algorithm but erases no key pair, so a `csr`'s `key_pair_id` FK still points at a live key pair). The
only cascade on `csr` is via its `key_pair_id` → `key_pair` FK when a key pair's material changes:
both `KeyPairErase` and `GenerateKeyPair` discard any CSR outstanding for that key pair
(`libspdm_db_clear_key_pair_csr()`), since a CSR built for the old key material is stale. The access
functions perform these cascades so no dangling child row can outlive its parent.

```c
/* readers (compose wire views; the *selected bank* readers take the negotiated algo/hash) */
uint8_t  libspdm_db_slot_state(const libspdm_db_t *db,
                               uint8_t bank_id, uint8_t slot_id);   /* returns 1..4 */
uint8_t  libspdm_db_supported_slot_mask(const libspdm_db_t *db, uint8_t bank_id);
uint8_t  libspdm_db_provisioned_slot_mask(const libspdm_db_t *db, uint8_t bank_id,
                                          bool multi_key);   /* multi_key gates the assoc clause */
uint8_t  libspdm_db_assoc_cert_slot_mask(const libspdm_db_t *db,
                                         uint8_t bank_id, uint8_t key_pair_id);
/* count slots (other than the given one) currently associated with key_pair_id; used to enforce
 * the ShareableCap cardinality in libspdm_db_associate_slot_key(). */
size_t   libspdm_db_count_key_pair_assoc_other(const libspdm_db_t *db, uint8_t key_pair_id,
                                               uint8_t except_bank_id, uint8_t except_slot_id);
bool     libspdm_db_get_cert_chain(const libspdm_db_t *db,
                                   uint8_t bank_id, uint8_t slot_id,
                                   void *chain, size_t *chain_size);  /* Table 39 chain */

/* writers (each enforces the invariants and touches exactly one row) */
bool libspdm_db_set_certificate(libspdm_db_t *db,
                                uint8_t bank_id, uint8_t slot_id,
                                bool multi_key, uint8_t key_pair_id, uint8_t certificate_info,
                                const void *der, size_t der_size,
                                const void *leaf_public_key, uint16_t leaf_public_key_len,
                                bool reset_required);  /* state 3 -> 4; multi_key=MULTI_KEY_CONN_RSP
                                                        * (wire KeyPairID==0 resolves to the slot's
                                                        * assoc in non-multikey); requires assoc match,
                                                        * algo match, leaf pubkey == key pair's
                                                        * public_key_info; -> cert_chain or pending */
bool libspdm_db_erase_certificate(libspdm_db_t *db,
                                  uint8_t bank_id, uint8_t slot_id,
                                  bool reset_required);  /* keep the key; clears cert_chain, or stages
                                                          * a present==false cert_chain_pending row */
bool libspdm_db_associate_slot_key(libspdm_db_t *db,
                                   uint8_t bank_id, uint8_t slot_id, uint8_t key_pair_id);
bool libspdm_db_dissociate_slot_key(libspdm_db_t *db,
                                    uint8_t bank_id, uint8_t slot_id);
                                                          /* state 3 -> 2; rejects if a committed cert
                                                           * is present (Erase it first; open #5);
                                                           * cascade-discards any staged pending cert */
bool libspdm_db_generate_key_pair(libspdm_db_t *db, uint8_t key_pair_id,
                                  const libspdm_db_algo_t *algo, uint16_t key_usage,
                                  const void *public_key_info, uint16_t public_key_info_len);
                                                          /* requires GenKeyCap; algo already selected;
                                                           * only if no assoc (OperationFailed else);
                                                           * discards any CSR for this key pair */
bool libspdm_db_erase_key_pair(libspdm_db_t *db, uint8_t key_pair_id);
                                                          /* requires ErasableCap; only if no assoc;
                                                           * discards any CSR for this key pair */
bool libspdm_db_set_key_usage(libspdm_db_t *db, uint8_t key_pair_id, uint16_t key_usage);
                                                          /* requires KeyUsageCap; subset of caps */
bool libspdm_db_set_key_algo(libspdm_db_t *db, uint8_t key_pair_id,
                             const libspdm_db_algo_t *algo);  /* requires AsymAlgoCap; cannot change
                                                               * algo once a key is generated */
bool libspdm_db_config_bank_algo(libspdm_db_t *db,
                                 uint8_t bank_id, const libspdm_db_algo_t *algo);
                                                          /* requires CONFIG_ALGO; algo must select
                                                           * exactly one algorithm (all-zero is
                                                           * rejected); no slot in the bank may have an
                                                           * associated key pair (state 3 or 4); clears
                                                           * all slot settings on success */
bool libspdm_db_apply_pending(libspdm_db_t *db);       /* reset handler: pending -> cert_chain */
```

## Access API implementations

Reference implementations of every function in [Access API](#access-api). They depend only on the
[Schema](#schema-c-structures) and the standard libspdm encodings (`SPDM_KEY_PAIR_CAP_*`,
`SPDM_SLOT_MANAGEMENT_*`, `SPDM_CERTIFICATE_INFO_CERT_MODEL_*`). Each writer enforces its invariants
and touches exactly one row (plus any cascade); each reader composes a wire view without mutating the
store. They are intentionally small — the value is that the invariants live in one place.

### Readers

```c
/* slot state 1..4, derived purely from row presence (see "The slot state is derived, never
 * stored"). The invalid combination (slot present, no assoc, but cert present) is asserted. */
uint8_t libspdm_db_slot_state(const libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id)
{
    LIBSPDM_ASSERT(db != NULL);

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->slot[bank_id][slot_id].present) {
        return 1;   /* does not exist */
    }
    if (!db->slot_key_assoc[bank_id][slot_id].present) {
        /* a provisioned slot must have its key associated; cert-without-assoc is invalid. */
        LIBSPDM_ASSERT(!db->cert_chain[bank_id][slot_id].present);
        return 2;   /* exists and empty */
    }
    if (!db->cert_chain[bank_id][slot_id].present) {
        return 3;   /* exists with key */
    }
    return 4;       /* exists with key and cert */
}

/* SupportedSlotMask (Param1 of GET_DIGESTS, GetBankInfo SlotMask): bit slot_id set <=> slot exists
 * (state >= 2). */
uint8_t libspdm_db_supported_slot_mask(const libspdm_db_t *db, uint8_t bank_id)
{
    uint8_t mask;
    uint8_t slot_id;

    LIBSPDM_ASSERT(db != NULL);

    mask = 0;
    if (bank_id >= db->num_banks) {
        return 0;
    }
    for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
        if (db->slot[bank_id][slot_id].present) {
            mask |= (uint8_t)(1u << slot_id);
        }
    }
    return mask;
}

/* ProvisionedSlotMask (Param2 of GET_DIGESTS): bit set <=> the slot has a certificate chain, OR --
 * only in a multikey connection -- it has an associated key pair (DSP0274 Table 41; see A1). The
 * caller passes multi_key = (MULTI_KEY_CONN_REQ || MULTI_KEY_CONN_RSP). */
uint8_t libspdm_db_provisioned_slot_mask(const libspdm_db_t *db, uint8_t bank_id, bool multi_key)
{
    uint8_t mask;
    uint8_t slot_id;

    LIBSPDM_ASSERT(db != NULL);

    mask = 0;
    if (bank_id >= db->num_banks) {
        return 0;
    }
    for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
        if (db->cert_chain[bank_id][slot_id].present ||
            (multi_key && db->slot_key_assoc[bank_id][slot_id].present)) {
            mask |= (uint8_t)(1u << slot_id);
        }
    }
    return mask;
}

/* AssocCertSlotMask (KEY_PAIR_INFO Table 111): the inverse projection of slot_key_assoc -- bit
 * slot_id set <=> slot (bank_id, slot_id) is associated with key_pair_id. bank_id is the key pair's
 * (unique) bank; not gated on multikey. */
uint8_t libspdm_db_assoc_cert_slot_mask(const libspdm_db_t *db,
                                        uint8_t bank_id, uint8_t key_pair_id)
{
    uint8_t mask;
    uint8_t slot_id;

    LIBSPDM_ASSERT(db != NULL);

    mask = 0;
    if ((bank_id >= db->num_banks) || (key_pair_id == 0)) {
        return 0;
    }
    for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
        const libspdm_db_slot_key_assoc_t *assoc = &db->slot_key_assoc[bank_id][slot_id];

        if (assoc->present && (assoc->key_pair_id == key_pair_id)) {
            mask |= (uint8_t)(1u << slot_id);
        }
    }
    return mask;
}

/* Count the slots associated with key_pair_id, EXCLUDING (except_bank_id, except_slot_id). Used by
 * libspdm_db_associate_slot_key() to enforce ShareableCap cardinality: a non-shareable key pair may
 * back at most one slot, so the count of OTHER slots must be 0 before a new association. Excluding
 * the target slot keeps re-association of the same slot idempotent. (A key pair maps to one bank, so
 * a consistent store has all its associations in that bank; scanning all banks is a cheap defensive
 * read that cannot under-count.) */
size_t libspdm_db_count_key_pair_assoc_other(const libspdm_db_t *db, uint8_t key_pair_id,
                                             uint8_t except_bank_id, uint8_t except_slot_id)
{
    size_t count;
    uint8_t bank_id;
    uint8_t slot_id;

    LIBSPDM_ASSERT(db != NULL);

    count = 0;
    for (bank_id = 0; bank_id < db->num_banks; bank_id++) {
        for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
            const libspdm_db_slot_key_assoc_t *assoc = &db->slot_key_assoc[bank_id][slot_id];

            if (!assoc->present || (assoc->key_pair_id != key_pair_id)) {
                continue;
            }
            if ((bank_id == except_bank_id) && (slot_id == except_slot_id)) {
                continue;   /* skip the slot we are (re-)associating */
            }
            count++;
        }
    }
    return count;
}

/* Read a slot's certificate chain (Table 39). Returns false if the slot is not provisioned (no
 * cert_chain row) or the caller buffer is too small. */
bool libspdm_db_get_cert_chain(const libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id,
                               void *chain, size_t *chain_size)
{
    const libspdm_db_cert_chain_t *cert;

    LIBSPDM_ASSERT((db != NULL) && (chain_size != NULL));

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->cert_chain[bank_id][slot_id].present) {
        return false;
    }
    cert = &db->cert_chain[bank_id][slot_id];
    if (*chain_size < cert->der_size) {
        *chain_size = cert->der_size;   /* report the required size */
        return false;
    }
    libspdm_copy_mem(chain, *chain_size, cert->der, cert->der_size);
    *chain_size = cert->der_size;
    return true;
}
```

### Writers

```c
/* Install (or stage) a certificate chain: state 3 -> 4 (the slot must ALREADY be associated). Per
 * the install ASSUMPTION (see the state-preconditions table), this model does NOT let SET_CERTIFICATE
 * create or re-point the association; it requires all three of:
 *   (1) assoc == 1: the slot is associated, and its key_pair_id == the request's key_pair_id;
 *   (2) algo is same: that key pair's current algorithm equals the bank algorithm; and
 *   (3) pubkey content is same: the chain's leaf public key (leaf_public_key/leaf_public_key_len,
 *       extracted by the caller) equals the key pair's public_key_info.
 * (1)/(2) failing is InvalidRequest; (3) failing is the Table 101 verification failure -- reject and
 * RETAIN any existing certificate (this function makes no change on failure). When reset_required is
 * true the write lands in cert_chain_pending and is committed by libspdm_db_apply_pending();
 * otherwise it commits to cert_chain directly (the single write/served store, see "One write, one
 * served value").
 *
 * RESOLVE AT WRITE (multikey): the request's KeyPairID is multikey-gated -- per Table 101 Param2 /
 * Table 147 it "shall be zero" when MULTI_KEY_CONN_RSP is false. The caller passes multi_key =
 * MULTI_KEY_CONN_RSP and the wire KeyPairID in key_pair_id. In non-multikey mode (multi_key == false)
 * key_pair_id is the wire 0; this function RESOLVES it to the slot's single implicit key pair (the
 * existing slot_key_assoc) before applying checks (1)-(3), so the stored/compared id is always the
 * real one (the write-side mirror of the "STORE REAL, GATE AT READ" rule). In multikey mode the wire
 * id must be non-zero and is used as-is. */
bool libspdm_db_set_certificate(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id,
                                bool multi_key, uint8_t key_pair_id, uint8_t certificate_info,
                                const void *der, size_t der_size,
                                const void *leaf_public_key, uint16_t leaf_public_key_len,
                                bool reset_required)
{
    libspdm_db_cert_chain_t *target;
    const libspdm_db_key_pair_t *key_pair;

    LIBSPDM_ASSERT((db != NULL) && ((der != NULL) || (der_size == 0)));

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->slot[bank_id][slot_id].present ||
        (der_size > LIBSPDM_DB_CERT_CHAIN_MAX)) {
        return false;
    }
    /* RESOLVE AT WRITE: in non-multikey the wire KeyPairID is 0; resolve it to the slot's single
     * implicit key pair (its existing association). The slot must be associated either way -- an
     * unassociated slot has nothing to resolve to and no real id to match. */
    if (!db->slot_key_assoc[bank_id][slot_id].present) {
        return false;
    }
    if (!multi_key) {
        if (key_pair_id != 0) {
            return false;   /* Table 101/147: KeyPairID shall be 0 in non-multikey */
        }
        key_pair_id = db->slot_key_assoc[bank_id][slot_id].key_pair_id;   /* the implicit key pair */
    }
    /* (1) assoc == 1: the (resolved) key pair must equal the slot's association. */
    if ((db->slot_key_assoc[bank_id][slot_id].key_pair_id != key_pair_id) ||
        (key_pair_id == 0) || (key_pair_id > db->total_key_pairs)) {
        return false;
    }
    key_pair = &db->key_pair[key_pair_id - 1];
    /* (2) algo is same: the key pair's current algorithm must equal the bank algorithm. */
    if ((key_pair->current_asym_algo != db->bank[bank_id].algo.asym_algo) ||
        (key_pair->current_pqc_asym_algo != db->bank[bank_id].algo.pqc_asym_algo)) {
        return false;
    }
    /* (3) pubkey content is same: the chain's leaf public key must match the key pair's
     * public_key_info (Table 101 chain-<->key-pair verification; on failure retain the existing
     * cert, i.e. make no change). */
    if ((leaf_public_key_len != key_pair->public_key_info_len) ||
        !libspdm_consttime_is_mem_equal(leaf_public_key, key_pair->public_key_info,
                                        leaf_public_key_len)) {
        return false;
    }

    target = reset_required ? &db->cert_chain_pending[bank_id][slot_id]
                            : &db->cert_chain[bank_id][slot_id];
    target->bank_id          = bank_id;
    target->slot_id          = slot_id;
    target->present          = true;   /* staged install: the shadow's present flag is true */
    target->certificate_info = certificate_info;
    target->der_size         = der_size;
    libspdm_copy_mem(target->der, sizeof(target->der), der, der_size);
    if (reset_required) {
        db->cert_chain_pending_valid[bank_id][slot_id] = true;   /* a commit is queued */
    }
    return true;
}

/* Erase a slot's certificate chain, KEEPING the key: state 4 -> 3 (DSP0274 "Erase keeps the key").
 * slot_key_assoc is untouched. Symmetric with libspdm_db_set_certificate's two-phase commit: when a
 * Responder advertises CERT_INSTALL_RESET_CAP and requires a reset to apply the erase, reset_required
 * is true and the erase is STAGED; otherwise it commits live.
 *
 * Erase uses the SAME shadow as install, distinguished only by the staged row's present flag:
 *  - reset_required == false (immediate): clear the committed cert_chain row now, and discard any
 *    pending commit for the slot so a later reset cannot re-commit it.
 *  - reset_required == true (staged): leave the committed cert_chain intact (a read in the same boot
 *    still returns it), stage a cert_chain_pending row with present == false (the "no cert" value)
 *    and set cert_chain_pending_valid, so libspdm_db_apply_pending() copies that row -- clearing the
 *    cert -- on the next reset. Staging here overwrites any previously staged install for the slot.
 *
 * Either way a pending install never outlives the erase that supersedes it (same staged-cert-
 * lifecycle concern as open spec question #4 -- a pending shadow must not outlive the committed state
 * it belongs to). */
bool libspdm_db_erase_certificate(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id,
                                  bool reset_required)
{
    LIBSPDM_ASSERT(db != NULL);

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->slot[bank_id][slot_id].present) {
        return false;
    }
    /* any previously staged commit (install or erase) is superseded by this erase; drop it first. */
    libspdm_db_clear_pending_cert_chain(db, bank_id, slot_id);
    if (reset_required) {
        /* stage the erase as a "no cert" shadow row (present == false); committed cert_chain stays
         * live until the reset copies the shadow over it. */
        db->cert_chain_pending[bank_id][slot_id].bank_id = bank_id;
        db->cert_chain_pending[bank_id][slot_id].slot_id = slot_id;
        db->cert_chain_pending[bank_id][slot_id].present = false;
        db->cert_chain_pending_valid[bank_id][slot_id]   = true;
        return true;
    }
    /* immediate erase. */
    libspdm_zero_mem(&db->cert_chain[bank_id][slot_id], sizeof(db->cert_chain[bank_id][slot_id]));
    db->cert_chain[bank_id][slot_id].bank_id = bank_id;
    db->cert_chain[bank_id][slot_id].slot_id = slot_id;
    db->cert_chain[bank_id][slot_id].present = false;
    return true;
}

/* Associate a slot with a key pair: state 2 -> 3. A slot's key pair must use the bank's algorithm
 * (Gap #3638), the key pair must allow association (CertAssocCap) and exist (public_key_info_len),
 * and ShareableCap cardinality must hold. This is the single authoritative association write. */
bool libspdm_db_associate_slot_key(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id,
                                   uint8_t key_pair_id)
{
    libspdm_db_key_pair_t *key_pair;

    LIBSPDM_ASSERT(db != NULL);

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->slot[bank_id][slot_id].present ||
        (key_pair_id == 0) || (key_pair_id > db->total_key_pairs)) {
        return false;
    }
    /* the key pair's current algorithm must equal the bank's algorithm (key_pair is indexed by
     * key_pair_id - 1). Both traditional and PQC are uint32_t, so this is a plain comparison. */
    key_pair = &db->key_pair[key_pair_id - 1];
    if ((key_pair->current_asym_algo != db->bank[bank_id].algo.asym_algo) ||
        (key_pair->current_pqc_asym_algo != db->bank[bank_id].algo.pqc_asym_algo)) {
        return false;   /* key pair algorithm does not match bank algorithm */
    }
    /* CertAssocCap: the Responder must allow changing the key-pair/slot association. */
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_CERT_ASSOC_CAP) == 0) {
        return false;
    }
    /* the key pair must actually exist (key material generated) before it can back a slot. This is
     * the "public_key_info_len == 0 => no slot_key_assoc may reference this key pair" invariant. */
    if (key_pair->public_key_info_len == 0) {
        return false;
    }
    /* ShareableCap cardinality (DSP0274 Table 112 / AssocCertSlotMask): a key pair without
     * ShareableCap may be associated with at most one slot. If it is not shareable and is already
     * associated with a different (bank, slot), reject the second association. */
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_SHAREABLE_CAP) == 0) {
        if (libspdm_db_count_key_pair_assoc_other(db, key_pair_id, bank_id, slot_id) != 0) {
            return false;
        }
    }
    db->slot_key_assoc[bank_id][slot_id].bank_id     = bank_id;
    db->slot_key_assoc[bank_id][slot_id].slot_id     = slot_id;
    db->slot_key_assoc[bank_id][slot_id].present     = true;
    db->slot_key_assoc[bank_id][slot_id].key_pair_id = key_pair_id;
    return true;
}

/* Dissociate a slot from its key pair (SET_KEY_PAIR_INFO ParameterChange, DesiredAssocCertSlotMask
 * bit cleared): state 3 -> 2. This is the single authoritative dissociation write.
 *
 * It CASCADE-DISCARDS any reset-required certificate staged for the slot in cert_chain_pending: that
 * chain was staged under this association (SET_CERTIFICATE requires the slot associated -- see
 * libspdm_db_set_certificate), so once the association is gone the staged chain is orphaned and must
 * not be committed onto an unassociated slot at the next reset. Dropping it here keeps the "a
 * provisioned slot must have its key associated" invariant true through reset (resolves open spec
 * question #4).
 *
 * A COMMITTED certificate already present in the slot (state 4) is rejected: the Requester must
 * Erase the certificate first (state 4 -> 3), per the DSP0274 de-provisioning order ("erase certs
 * -> dissociate -> erase key"). This preserves the model's "provisioned slot must have its key
 * associated" invariant. Whether the spec actually requires this rejection (vs. just removing the
 * association and leaving the cert) is open spec question #5; this model takes the rejecting reading. */
bool libspdm_db_dissociate_slot_key(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id)
{
    LIBSPDM_ASSERT(db != NULL);

    if ((bank_id >= db->num_banks) || (slot_id >= db->config.db_max_slots) ||
        !db->slot[bank_id][slot_id].present) {
        return false;
    }
    /* a committed certificate must be erased before dissociating (state 4 -> 3 first); open #5. */
    if (db->cert_chain[bank_id][slot_id].present) {
        return false;
    }
    /* drop the association (state 3 -> 2). */
    libspdm_zero_mem(&db->slot_key_assoc[bank_id][slot_id],
                     sizeof(db->slot_key_assoc[bank_id][slot_id]));
    db->slot_key_assoc[bank_id][slot_id].bank_id = bank_id;
    db->slot_key_assoc[bank_id][slot_id].slot_id = slot_id;
    db->slot_key_assoc[bank_id][slot_id].present = false;
    /* cascade-discard any staged reset-required cert queued under the association (open question #4):
     * with the association gone it can no longer be committed onto an unassociated slot at reset. */
    libspdm_db_clear_pending_cert_chain(db, bank_id, slot_id);
    return true;
}

/* GenerateKeyPair (SET_KEY_PAIR_INFO): generate key material and set the current algorithm/usage of
 * a key pair. Requires GenKeyCap. The current algorithm must be a single bit within the key pair's
 * AsymAlgoCapabilities/PqcAsymAlgoCapabilities and the usage a subset of KeyUsageCapabilities. (The
 * actual key generation is a HAL call; here we record the resulting public key and configuration.)
 *
 * Per DSP0274 "Key pair ID modification error handling", GenerateKeyPair has two STATE preconditions
 * beyond the capability gate (both -> OperationFailed if violated, here reported as false):
 *   - the key pair must NOT be associated with any certificate slot; and
 *   - an asymmetric algorithm must already be selected (generate is bound to the current algorithm).
 * The caller passes that already-selected algorithm in *algo; this function records it and the key.
 * On success it also discards any CSR outstanding for this key pair (the new key invalidates a CSR
 * built for the old one). */
bool libspdm_db_generate_key_pair(libspdm_db_t *db, uint8_t key_pair_id,
                                  const libspdm_db_algo_t *algo, uint16_t key_usage,
                                  const void *public_key_info, uint16_t public_key_info_len)
{
    libspdm_db_key_pair_t *key_pair;
    uint8_t bank_id;

    LIBSPDM_ASSERT((db != NULL) && (algo != NULL));

    if ((key_pair_id == 0) || (key_pair_id > db->total_key_pairs) ||
        (public_key_info_len == 0) || (public_key_info_len > LIBSPDM_DB_PUBKEY_INFO_MAX)) {
        return false;
    }
    key_pair = &db->key_pair[key_pair_id - 1];
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_GEN_KEY_CAP) == 0) {
        return false;
    }
    /* State precondition: an asymmetric algorithm must already be selected (OperationFailed). A
     * GenerateKeyPair with no algorithm selected has nothing to bind the key to. */
    if ((algo->asym_algo == 0) && (algo->pqc_asym_algo == 0)) {
        return false;
    }
    /* exactly one algorithm bit total, within the corresponding capability bitmap. */
    if (!libspdm_db_algo_is_single_supported(algo, key_pair->asym_algo_capabilities,
                                             key_pair->pqc_asym_algo_capabilities)) {
        return false;
    }
    /* State precondition: the key pair must not be associated with any certificate slot
     * (OperationFailed) -- the certs must be erased and the slots dissociated first. */
    for (bank_id = 0; bank_id < db->num_banks; bank_id++) {
        if (libspdm_db_assoc_cert_slot_mask(db, bank_id, key_pair_id) != 0) {
            return false;
        }
    }
    /* current usage must be a subset of the advertised key-usage capabilities. */
    if ((key_usage & ~key_pair->key_usage_capabilities) != 0) {
        return false;
    }
    key_pair->current_asym_algo     = algo->asym_algo;
    key_pair->current_pqc_asym_algo = algo->pqc_asym_algo;
    key_pair->current_key_usage     = key_usage;
    key_pair->public_key_info_len   = public_key_info_len;
    libspdm_copy_mem(key_pair->public_key_info, sizeof(key_pair->public_key_info),
                     public_key_info, public_key_info_len);
    /* generating new key material invalidates any CSR outstanding for this key pair (it was for the
     * old key); discard it. */
    libspdm_db_clear_key_pair_csr(db, key_pair_id);
    return true;
}

/* KeyPairErase (SET_KEY_PAIR_INFO): remove a key pair's key material: state 3 -> 2 for every slot it
 * backs. Requires ErasableCap and -- per DSP0274 -- that no slot is still associated with it (the
 * caller dissociates first), preserving the "public_key_info_len == 0 => no assoc" invariant. On
 * success it also discards any CSR outstanding for this key pair, including a PENDING_RESET tag (the
 * csr.key_pair_id -> key_pair cascade). */
bool libspdm_db_erase_key_pair(libspdm_db_t *db, uint8_t key_pair_id)
{
    libspdm_db_key_pair_t *key_pair;
    uint8_t bank_id;

    LIBSPDM_ASSERT(db != NULL);

    if ((key_pair_id == 0) || (key_pair_id > db->total_key_pairs)) {
        return false;
    }
    key_pair = &db->key_pair[key_pair_id - 1];
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_ERASABLE_CAP) == 0) {
        return false;
    }
    /* must not be associated with any slot. */
    for (bank_id = 0; bank_id < db->num_banks; bank_id++) {
        if (libspdm_db_assoc_cert_slot_mask(db, bank_id, key_pair_id) != 0) {
            return false;
        }
    }
    key_pair->current_asym_algo     = 0;
    key_pair->current_pqc_asym_algo = 0;
    key_pair->current_key_usage     = 0;
    key_pair->public_key_info_len   = 0;
    libspdm_zero_mem(key_pair->public_key_info, sizeof(key_pair->public_key_info));
    /* erasing the key material invalidates any CSR outstanding for this key pair -- including a
     * PENDING_RESET tag -- so discard it (the csr.key_pair_id -> key_pair cascade). */
    libspdm_db_clear_key_pair_csr(db, key_pair_id);
    return true;
}

/* Set a key pair's CurrentKeyUsage (SET_KEY_PAIR_INFO). Requires KeyUsageCap; the new usage must be
 * a subset of KeyUsageCapabilities. Usage is per key pair, never per slot. */
bool libspdm_db_set_key_usage(libspdm_db_t *db, uint8_t key_pair_id, uint16_t key_usage)
{
    libspdm_db_key_pair_t *key_pair;

    LIBSPDM_ASSERT(db != NULL);

    if ((key_pair_id == 0) || (key_pair_id > db->total_key_pairs)) {
        return false;
    }
    key_pair = &db->key_pair[key_pair_id - 1];
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_KEY_USAGE_CAP) == 0) {
        return false;
    }
    if ((key_usage & ~key_pair->key_usage_capabilities) != 0) {
        return false;
    }
    key_pair->current_key_usage = key_usage;
    return true;
}

/* Set a key pair's CurrentAsymAlgo/CurrentPqcAsymAlgo (SET_KEY_PAIR_INFO ParameterChange). Requires
 * AsymAlgoCap; the algorithm must be a single bit within the capability bitmaps.
 *
 * Per DSP0274 "Key pair ID modification error handling", once a key pair has been GENERATED the
 * Responder shall not change a parameter that affects the generated key, such as the asymmetric
 * algorithm (the key value is bound to CurrentAsymAlgo). So a *change* of algorithm is rejected when
 * key material exists (public_key_info_len != 0); re-selecting the same algorithm is a no-op and
 * allowed. (A key pair is also never associated to a slot without key material, so the generated
 * check subsumes the old association check.) */
bool libspdm_db_set_key_algo(libspdm_db_t *db, uint8_t key_pair_id, const libspdm_db_algo_t *algo)
{
    libspdm_db_key_pair_t *key_pair;

    LIBSPDM_ASSERT((db != NULL) && (algo != NULL));

    if ((key_pair_id == 0) || (key_pair_id > db->total_key_pairs)) {
        return false;
    }
    key_pair = &db->key_pair[key_pair_id - 1];
    if ((key_pair->capabilities & SPDM_KEY_PAIR_CAP_ASYM_ALGO_CAP) == 0) {
        return false;
    }
    if (!libspdm_db_algo_is_single_supported(algo, key_pair->asym_algo_capabilities,
                                             key_pair->pqc_asym_algo_capabilities)) {
        return false;
    }
    /* A generated key is bound to its algorithm: reject a *different* algorithm once key material
     * exists; re-selecting the current algorithm is an allowed no-op. */
    if ((key_pair->public_key_info_len != 0) &&
        ((key_pair->current_asym_algo != algo->asym_algo) ||
         (key_pair->current_pqc_asym_algo != algo->pqc_asym_algo))) {
        return false;
    }
    key_pair->current_asym_algo     = algo->asym_algo;
    key_pair->current_pqc_asym_algo = algo->pqc_asym_algo;
    return true;
}

/* ManageBank ConfigAlgo: set a bank's algorithm. Requires the bank's CONFIG_ALGO attribute; the
 * selected algorithm to be in the bank's AvailableAsymAlgo / AvailablePqcAsymAlgo (DSP0274 Table 145:
 * "the set bit shall match one of the algorithms ... in the AsymAlgoCapabilities field of the
 * BankDetails response", and an algorithm "already configured for another Bank" is rejected --
 * together exactly Select in Available, since Available = Capabilities minus other banks' algorithms);
 * and -- per DSP0274 Table 141 -- NO slot in the
 * bank to have an associated key pair (i.e. no slot in state 3 OR state 4; only states 1/2 are
 * allowed). A state-3 slot (key, no cert) is rejected just like a state-4 slot (cert): the Requester
 * must dissociate the key via SET_KEY_PAIR_INFO (erasing the cert first for state 4) BEFORE
 * ConfigAlgo, so ConfigAlgo never implicitly drops an association or mutates a key pair's derived
 * AssocCertSlotMask.
 *
 * In the libspdm implementation the Select-in-Available check is performed by the responder lib
 * (it reads the bank's Available* via the GetBankDetails HAL and rejects a non-member with
 * InvalidRequest), so it uses the same availability the GetBankDetails SubCode reports. This
 * function keeps the equivalent membership/uniqueness checks as a self-contained backstop for
 * callers that invoke it directly. On success it clears all slot settings in the
 * bank (DSP0274 "clear all slot settings" cascade); since only states 1/2 remain, there is no
 * slot_key_assoc/cert_chain row to drop, so the cascade clears only residual slot attributes. It
 * does NOT touch the CSR pool: a csr is keyed by CSRTrackingTag (no bank_id/slot_id) and ConfigAlgo
 * erases no key pair, so every csr's key_pair_id still references a live key pair.
 *
 * ConfigAlgo must select EXACTLY ONE algorithm: an all-zero algo (no SelectAsymAlgo/SelectPqcAsymAlgo
 * bit set) is rejected. Table 145's "no more than one bit" bounds the upper count (one algorithm per
 * Bank); it does not permit zero. There is no "unconfigure the bank" operation -- a bank is in the
 * Table 151 "not yet selected" state only before it has ever been configured. */
bool libspdm_db_config_bank_algo(libspdm_db_t *db, uint8_t bank_id, const libspdm_db_algo_t *algo)
{
    uint8_t other;
    uint8_t slot_id;
    bool has_asym;
    bool has_pqc;

    LIBSPDM_ASSERT((db != NULL) && (algo != NULL));

    if (bank_id >= db->num_banks) {
        return false;
    }
    if ((db->bank[bank_id].bank_attributes & SPDM_SLOT_MANAGEMENT_BANK_ATTRIBUTE_CONFIG_ALGO) == 0) {
        return false;
    }
    /* exactly one algorithm bit total, in exactly one of the two fields (all-zero is rejected;
     * "no more than one" never permits zero). */
    has_asym = (algo->asym_algo != 0);
    has_pqc  = (algo->pqc_asym_algo != 0);
    if (has_asym == has_pqc) {
        return false;   /* neither set (all-zero), or both set */
    }
    if (has_asym && ((algo->asym_algo & (algo->asym_algo - 1)) != 0)) {
        return false;   /* more than one traditional bit */
    }
    if (has_pqc && ((algo->pqc_asym_algo & (algo->pqc_asym_algo - 1)) != 0)) {
        return false;   /* more than one PQC bit */
    }
    /* no slot in the bank may have an associated key pair: a state-3 slot (key, no cert) is rejected
     * just like a state-4 slot (a cert implies an association). The Requester must dissociate (and
     * erase any cert) via SET_KEY_PAIR_INFO first, so ConfigAlgo never implicitly drops one. */
    for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
        if (db->slot_key_assoc[bank_id][slot_id].present) {
            return false;
        }
    }
    /* Select shall be in the bank's AvailableAsymAlgo / AvailablePqcAsymAlgo (DSP0274 Table 145).
     * Available = Capabilities minus the algorithms already configured for another bank.
     * Capabilities is the bank's stored AsymAlgoCapabilities / PqcAsymAlgoCapabilities device fact
     * (the same value reported by GetBankDetails); the uniqueness check below is the "minus other
     * banks" half, so this is the "in Capabilities" half. (algo is guaranteed non-all-zero by the
     * one-bit check above.) */
    if (((algo->asym_algo & db->bank[bank_id].asym_algo_capabilities) != algo->asym_algo) ||
        ((algo->pqc_asym_algo & db->bank[bank_id].pqc_asym_algo_capabilities) !=
         algo->pqc_asym_algo)) {
        return false;
    }
    /* uniqueness across configured banks: the "minus algorithms assigned to another bank" half of
     * the AvailableAsymAlgo rule. */
    for (other = 0; other < db->num_banks; other++) {
        if ((other != bank_id) &&
            (db->bank[other].algo.asym_algo == algo->asym_algo) &&
            (db->bank[other].algo.pqc_asym_algo == algo->pqc_asym_algo)) {
            return false;
        }
    }
    db->bank[bank_id].algo = *algo;
    /* "clear all slot settings" cascade (DSP0274). The precondition above rejected any association,
     * and a dissociate already discarded each slot's pending cert (open spec question #4), so no
     * per-slot child state remains; libspdm_db_clear_slot() asserts that invariant per slot. */
    for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
        libspdm_db_clear_slot(db, bank_id, slot_id);
    }
    return true;
}

/* Reset handler: commit every pending (ResetRequired) write atomically. Called once after a device
 * reset, before serving any command. A staged cert can only exist for a still-associated slot,
 * because dissociating a slot cascade-discards its pending cert (libspdm_db_dissociate_slot_key,
 * open spec question #4), so this never commits a chain onto an unassociated slot. */
bool libspdm_db_apply_pending(libspdm_db_t *db)
{
    uint8_t bank_id;
    uint8_t slot_id;
    uint8_t kp;

    LIBSPDM_ASSERT(db != NULL);

    for (bank_id = 0; bank_id < db->num_banks; bank_id++) {
        for (slot_id = 0; slot_id < db->config.db_max_slots; slot_id++) {
            if (db->cert_chain_pending_valid[bank_id][slot_id]) {
                /* copy the staged row verbatim -- present flag and all. A staged install
                 * (present == true) provisions the slot; a staged erase (present == false) clears
                 * it. Either way the result is exactly the shadow row. */
                db->cert_chain[bank_id][slot_id] = db->cert_chain_pending[bank_id][slot_id];
            }
            libspdm_db_clear_pending_cert_chain(db, bank_id, slot_id);
        }
        if (db->bank_algo_pending_valid[bank_id]) {
            db->bank[bank_id].algo = db->bank_algo_pending[bank_id];
            db->bank_algo_pending_valid[bank_id] = false;
        }
    }
    for (kp = 0; kp < db->total_key_pairs; kp++) {
        if (db->key_pair_pending_valid[kp]) {
            db->key_pair[kp] = db->key_pair_pending[kp];
            db->key_pair_pending_valid[kp] = false;
        }
    }
    return true;
}
```

### Internal helpers

Four small helpers keep the writers above readable; they are not part of the public Access API.

```c
/* true iff algo names exactly one algorithm (a single bit, in either the traditional OR the PQC
 * field but not both) and that bit is within the supplied capability bitmaps. Used by
 * generate_key_pair / set_key_algo to enforce the "at most one current bit, within capabilities"
 * invariant. */
static bool libspdm_db_algo_is_single_supported(const libspdm_db_algo_t *algo,
                                                uint32_t asym_caps, uint32_t pqc_caps)
{
    bool has_asym = (algo->asym_algo != 0);
    bool has_pqc  = (algo->pqc_asym_algo != 0);

    if (has_asym == has_pqc) {
        return false;   /* neither set, or both set */
    }
    if (has_asym) {
        return ((algo->asym_algo & (algo->asym_algo - 1)) == 0) &&     /* single bit */
               ((algo->asym_algo & ~asym_caps) == 0);                  /* within caps */
    }
    return ((algo->pqc_asym_algo & (algo->pqc_asym_algo - 1)) == 0) &&
           ((algo->pqc_asym_algo & ~pqc_caps) == 0);
}

/* Discard any reset-required commit staged for a slot: clears both the cert_chain_pending shadow row
 * (install or erase) and its cert_chain_pending_valid flag. A slot's pending shadow must not outlive
 * the association/committed state it was staged under, so this is called wherever that parent state
 * goes away -- on dissociate (libspdm_db_dissociate_slot_key) and on immediate certificate erase
 * (libspdm_db_erase_certificate) -- and as the post-commit cleanup in libspdm_db_apply_pending(). */
static void libspdm_db_clear_pending_cert_chain(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id)
{
    libspdm_zero_mem(&db->cert_chain_pending[bank_id][slot_id],
                     sizeof(db->cert_chain_pending[bank_id][slot_id]));
    db->cert_chain_pending_valid[bank_id][slot_id] = false;
}

/* The ManageBank ConfigAlgo "clear all slot settings" cascade for one slot. By the time ConfigAlgo
 * runs, its precondition has rejected the call unless every slot in the bank is in state 1/2 -- no
 * slot_key_assoc, hence (a cert implies an association) no cert_chain -- and a dissociate has already
 * discarded each slot's pending cert (libspdm_db_clear_pending_cert_chain via the dissociate path).
 * So a slot reaching here has NO per-slot child state left to clear; this function only ASSERTS that
 * invariant rather than clearing anything. (A CSR is not a child of the slot -- it stores no
 * bank_id/slot_id and is keyed by CSRTrackingTag -- so it is out of scope here.) */
static void libspdm_db_clear_slot(libspdm_db_t *db, uint8_t bank_id, uint8_t slot_id)
{
    LIBSPDM_ASSERT(!db->slot_key_assoc[bank_id][slot_id].present);
    LIBSPDM_ASSERT(!db->cert_chain[bank_id][slot_id].present);
    LIBSPDM_ASSERT(!db->cert_chain_pending_valid[bank_id][slot_id]);
}

/* Discard every CSR transaction for key_pair_id (the csr.key_pair_id -> key_pair ON DELETE CASCADE).
 * A csr is a child of its key pair, so when the key material is erased (KeyPairErase) or regenerated
 * (GenerateKeyPair) any outstanding CSR for that key pair -- including a PENDING_RESET tag awaiting a
 * post-reset retrieval -- is stale and is dropped. The csr pool is small (LIBSPDM_DB_MAX_CSR), so a
 * linear scan is fine. */
static void libspdm_db_clear_key_pair_csr(libspdm_db_t *db, uint8_t key_pair_id)
{
    size_t i;

    for (i = 0; i < LIBSPDM_ARRAY_SIZE(db->csr); i++) {
        if (db->csr[i].present && (db->csr[i].key_pair_id == key_pair_id)) {
            libspdm_zero_mem(&db->csr[i], sizeof(db->csr[i]));
        }
    }
}
```

## Mapping to the libspdm sample

The sample can realize the same model with the `libspdm_db_t` arrays above (or keep its current
fixed arrays, extended with the one authoritative association):

| Relation | Sample realization |
| -------- | ------------------ |
| `libspdm_db_algo_t` | a value type (Table 113/114 wire bits); the existing algorithm encode/decode helpers, not a stored table |
| `key_pair` | the `GET_KEY_PAIR_INFO` table (already present) |
| `bank` | `m_slot_management_bank[]` (derived from key pairs today) |
| `slot` | `bank->slots[]` (existence == in the array) |
| `slot_key_assoc` | a `key_pair_id` field on the slot, with the inverse computed for `AssocCertSlotMask` |
| `cert_chain` | the per-slot certificate NVM file (already the single source of truth) |
| `csr` | the existing CSR NVM / `CSRTrackingTag` state |

The key change to resolve the gaps is to make the **association** (`slot_key_assoc`) and the
**certificate presence** (`cert_chain`) single authoritative facts that `GET_DIGESTS`,
`GET_KEY_PAIR_INFO`, and the `SLOT_MANAGEMENT` SubCodes all *read*, instead of each command keeping
its own array. This document is the schema to converge them on.

## Capacity and fidelity limitations

The capacities here are **deliberate sample limits**, recorded in the self-descriptive `config`
header so a consumer knows the dimensions. They are below the spec maxima and may be raised (the
arrays and `config` scale directly); the relational design does not depend on the specific values.

| Item | Sample value | Spec allows | Note |
| ---- | ------------ | ----------- | ---- |
| `LIBSPDM_DB_MAX_BANKS` | 16 | `BankID` 0–239 | A real responder need not impose a fixed bank maximum; this is a sample storage cap, not a protocol limit. |
| `LIBSPDM_DB_MAX_KEY_PAIRS` | 16 | `TotalKeyPairs` is `uint8` (up to 255) | Sample storage cap. |
| `SlotSize` | one `LIBSPDM_DB_CERT_CHAIN_MAX` for all slots | `SlotElement.SlotSize` is per-slot (Table 152) | The model reports the same capacity for every slot; heterogeneous per-slot sizes would need a per-slot capacity field. |
| dense arrays + full `cert_chain_pending` | `[16][8]` materialized; two cert buffers/slot | — | Sparse data in fully-materialized arrays and a full pending shadow; an implementation cost, not a logical limit. |

## Open spec questions

These are points in DSP0274 that this review found ambiguous; they are recorded here as open
questions for a spec clarification. The data model takes the most consistent reading available but
the resolution may change some details above.

4. **What happens to a staged (reset-required) certificate when its slot is dissociated before the
   reset?** A reset-required `SET_CERTIFICATE` stages the chain in `cert_chain_pending[bank][slot]`
   and defers the commit to the next reset (`libspdm_db_apply_pending()`). The staging step requires
   the slot to be associated with a key pair (state 3/4) — that holds when the certificate is staged.
   But nothing requires the association to *persist* until the reset. Consider the flow:

   1. `SET_CERTIFICATE(reset_required=true)` on an associated slot → stages
      `cert_chain_pending[bank][slot]` (the association exists at stage time). No reset yet.
   2. The Requester dissociates the key via `SET_KEY_PAIR_INFO` → `slot_key_assoc[bank][slot]` is
      cleared. Nothing in the model (or the spec) clears the pending shadow on dissociate.

   Now the slot is back in state 2 (exists, no key, no cert) in the committed view, yet a pending
   certificate for it is still staged. DSP0274 defines `SET_CERTIFICATE`'s `ResetRequired` flow and
   the `SET_KEY_PAIR_INFO` dissociation separately and does **not** state their interaction: whether
   dissociating a slot must (a) be **rejected** while a reset-required certificate is staged for it,
   (b) **discard** the staged certificate as a side effect, or (c) leave the staged certificate to be
   committed on reset (re-creating an association implicitly, or committing a cert onto an
   unassociated slot — which violates the "a provisioned slot must have its key associated"
   invariant) is unspecified.

   This also reaches `ManageBank ConfigAlgo` (open question #2's resolution): `ConfigAlgo` gates on
   the *committed* `slot_key_assoc`, not on `cert_chain_pending`, so a slot dissociated per the flow
   above would otherwise pass the `ConfigAlgo` precondition while still carrying a staged certificate.
   Three consistent options were considered:
   * **Reject the dissociate** while a reset-required certificate is staged for the slot
     (`OperationFailed`) — symmetric with the other "finish the in-flight transaction first" rules.
   * **Cascade-discard** the staged certificate when the slot is dissociated — consistent with the
     model's referential cascade (`cert_chain_pending[bank][slot]` is slot-scoped child state, so it
     should not outlive the association it was staged under).
   * **Validate at commit time** — keep the staged certificate but have `libspdm_db_apply_pending()`
     skip (or reject) a pending cert whose slot is no longer associated at reset time.

   **Assumption taken by this model: (b) cascade-discard.** Dissociating a slot
   (`libspdm_db_dissociate_slot_key()`) clears `slot_key_assoc[bank][slot]` **and** discards the
   slot's `cert_chain_pending`, because the staged chain was queued under that association and must
   not commit onto an unassociated slot at the next reset. With the pending shadow gone at dissociate
   time, `libspdm_db_apply_pending()` only ever commits a chain for a still-associated slot, so the
   "a provisioned slot must have its key associated" invariant holds through reset. (This is a chosen
   reading, recorded here pending a spec clarification; a Responder that instead rejected the
   dissociate, or validated at commit time, would also be consistent with DSP0274 as written.) The
   `ManageBank ConfigAlgo` path is then automatically safe: a dissociated slot carries no pending
   cert, so `ConfigAlgo`'s `libspdm_db_clear_slot()` finds nothing to clean up and merely asserts it.

   > NOTE: This question concerns the **staged (reset-required)** certificate only. What a dissociate
   > does about a **committed** certificate already present in the slot (state 4) is a separate
   > matter — see open spec question #5.

5. **What does a dissociate do when the slot still holds a *committed* certificate (state 4)?** Per
   Table 115, `DesiredAssocCertSlotMask` describes the operation purely in terms of the association:
   "The Responder shall either remove an association or create an association between the
   corresponding certificate slot and the requested `KeyPairID`, depending on the value of each bit."
   It says **nothing about the certificate** — read literally, clearing a slot's bit just removes the
   association and leaves the resident `cert_chain` untouched. DSP0274's §"Key pair ID modification
   error handling" adds no `InvalidState`/`OperationFailed` clause for "dissociate a slot that still
   has a certificate"; the only related normative guidance is the recommended **de-provisioning
   order** ("erase all certificate chains … *then* … erase the key pair", a *should*, not a hard
   precondition on the dissociate op).

   The tension is with this model's state invariant. The literal reading makes **"certificate
   present, no association"** reachable: `slot` + `cert_chain` + **no** `slot_key_assoc`. The model
   currently calls that combination **invalid** (see [The slot state is derived, never
   stored](#the-slot-state-is-derived-never-stored): "a provisioned slot must have its key
   associated") and `libspdm_db_slot_state()` asserts against it. So one of the two must give:
   * **(A) Relax the invariant** — accept "cert present, no association" as a legal degenerate state
     (the literal Table 115 reading), dropping the assert and extending the 4-state derivation.
   * **(B) Keep the invariant by rejecting the dissociate** — reject (`OperationFailed`/`InvalidState`)
     while a committed `cert_chain` is present, requiring the Requester to Erase the certificate first
     (state 4 → 3), consistent with the recommended de-provisioning order.
   * **(C) Keep the invariant by auto-erasing** — drop the committed `cert_chain` as a side effect of
     the dissociate. This contradicts the "Erase keeps the key, dissociate is separate" structure and
     silently destroys a provisioned certificate, so it is the least attractive.

   **Assumption taken by this model: (B) reject.** `libspdm_db_dissociate_slot_key()` returns false
   when `cert_chain[bank][slot].present`, so the only path out of state 4 is Erase → dissociate. This
   keeps the invariant and matches the documented de-provisioning order, but it is a **stricter**
   behavior than Table 115's bare "remove an association" wording — a Responder taking reading (A)
   (just change the association, leave the cert) would also conform to the text. Recorded pending a
   spec clarification on whether "cert present, no association" is a legal state.

6. **Must `SET_CERTIFICATE` install onto an already-associated slot, or may it create/re-point the
   association?** DSP0274 frames the request's `KeyPairID` as "the desired asymmetric key pair **to
   associate with** `SlotID`" (Table 101 `Param2`; Table 147 `KeyPairID`), and the only match it
   explicitly mandates is between the **certificate chain and that `KeyPairID`/model**: "the Responder
   should verify that contents of the certificate chain meet the requirements … for the requested
   certificate model **and key pair** … if it does not, the Responder shall retain the current
   certificate" (§"SET_CERTIFICATE", Table 101 notes). DSP0274 states **no** precondition that the
   slot be associated first, and has **no** concept of a "mismatch with a previously-associated
   `KeyPairID`" — read literally, the request *is* the association authority and may move a slot from
   state 2 directly to state 4, creating or re-pointing the association as part of the install.

   This model takes the **stricter** reading (see the install ASSUMPTION after the state-preconditions
   table): a `SET_CERTIFICATE` install requires the slot to be **already associated**
   (`SET_KEY_PAIR_INFO` first), the request's `KeyPairID` must **equal** the existing association, and
   the model additionally enforces algorithm-agreement and a leaf-public-key match. Concretely it
   requires all of:
   * **(1) assoc == 1** — `slot_key_assoc[bank][slot].present` and `key_pair_id == KeyPairID`;
   * **(2) algo is same** — the associated key pair's current algorithm equals the bank algorithm; and
   * **(3) pubkey content is same** — the chain's leaf public key equals the key pair's
     `public_key_info` (the chain-↔-key-pair match DSP0274 actually requires).

   (1)/(2) failing is `InvalidRequest`; (3) failing is the Table 101 verification failure (reject and
   retain any existing certificate). A Responder taking the literal reading (associate via `KeyPairID`
   during install, state 2 → 4) would also conform to DSP0274. Open questions: (a) Must the slot be
   pre-associated, or may `SET_CERTIFICATE` establish the association? (b) If a different `KeyPairID`
   is supplied than the slot's current association, is that an error (this model) or a re-association
   (literal reading)? (c) Is the leaf-public-key match (3) required, or only the looser "meets the
   requirements for the requested model and key pair" of Table 101? Recorded pending a spec
   clarification; this model takes (a)=pre-associated, (b)=error, (c)=required.

## Notes and non-goals

* "Selected bank" and the negotiated algorithm are **connection** state, not device state, so they
  are not stored in these tables; they are parameters of the read queries. The selected-bank readers
  (`slot_state`, `*_slot_mask`, `Digest`) take no algorithm parameter because the bank is *selected
  by* the negotiated algorithm — within the selected bank everything matches by construction, so the
  connection-dependence of `ProvisionedSlotMask`/`Digest` is discharged by the bank=algo identity.
* The legacy `SET_CERTIFICATE`/`GET_CERTIFICATE` "selected bank aliases the BankID-less slot"
  behavior is **out of scope** here: this model addresses everything as `(bank_id, slot_id)` and
  treats selected-bank aliasing as connection-layer behavior, not device state.
* `GenerateKeyPair` may carry `DesiredAssocCertSlotMask` in the same request (generate-and-associate
  atomically). The write table lists generate and associate as separate steps for clarity; an
  implementation may fuse them, applying the same `CertAssocCap`/`ShareableCap` checks.
* This is a device-backend data model, not an SPDM wire change. No message format is altered.
* Capability bits (in `key_pair.capabilities` and the `CONFIG_ALGO` bit of `bank.bank_attributes`)
  are immutable device facts;
  only the `current_*` fields and the `slot`/`slot_key_assoc`/`cert_chain`/`csr` rows are mutated by
  `SET_*` commands.
