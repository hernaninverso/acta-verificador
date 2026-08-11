---
name: signature-coverage-audit
version: 0.1.0
license: Apache-2.0
description: >
  Use when writing, reviewing, or debugging anything that signs, hashes, or verifies a
  structure — signed receipts, audit trails, evidence chains, webhook payloads, licence
  tokens, signed manifests, attestations — or when a tool reports "valid", "verified", or
  "signature OK" and you need to know what that word actually covers. Checks that every
  field a human or a program can READ is inside the hash or the signature; that the
  allowlist of signed fields is closed rather than a blocklist that skips `_`-prefixed or
  "annotation" keys; that the envelope is signed at the same level it is read at; and that
  a public key taken from inside the signed file is never reported as proof of origin.
  Triggers on "verify this signature", "is this receipt genuine", "check the audit trail",
  "canonical JSON", "sign the payload", "tamper-proof", "is this bundle valid", "did anyone
  modify this file".
---

# Signature coverage audit

A signature is only worth what it covers. The bug in this skill is not "the crypto is
weak" — the crypto is almost always fine. It is that **something readable sits outside
what was signed**, so an attacker can write text that a human or a program reads as
verified, without touching a single signed byte.

This showed up in **three independent systems on the same day**, written by different
people at different times. It is not exotic. Assume it is present until you have checked.

## The four checks

Run all four. Each has caught a real defect.

### 1. Every readable field is inside the hash

List the fields a consumer can read. List the fields that enter the hash. **They must be
the same set.** Any field in the first list and not in the second is an injection channel.

The classic excuse is a field "for annotations" or "for comments" — deliberately excluded
so it can be edited without breaking the signature. That is exactly the hole: it lets an
attacker add `"_note": "this system is fraudulent"` to a legitimately signed record, and
the verifier still reports *verified*.

### 2. The allowlist is CLOSED, at every level

```python
# WRONG — a blocklist. Every field someone invents later is signed by nobody.
fields = {k: v for k, v in record.items() if not k.startswith("_")}

# RIGHT — a closed allowlist, and unknown keys are a hard error.
SIGNED = frozenset({"id", "issued_at", "subject", "claim", "evidence"})
extra = set(record) - SIGNED
if extra:
    raise ValueError(f"unknown fields, refusing to sign or verify: {sorted(extra)}")
```

Do this at **every level**: the root object, each nested block, and **each element of every
list**. One unguarded level is the whole hole. A real case had the root fixed and the
nested block still open.

### 3. The envelope is signed at the level it is read at

```json
{"payload": {...}, "sig": "...", "answer": "YES"}
```

If the signature covers `payload` but the consumer reads `receipt["answer"]`, then
`answer` is written by whoever last touched the file — including any intermediary. The
verifier says `valid: true` and it is telling the truth about the wrong thing.

**Sign the envelope, or read only from inside what was signed.** Never mix.

### 4. A key from inside the file proves nothing about origin

Verifying a signature against a public key that travels **inside the same file** is
circular: an attacker who rewrites the record also rewrites the key, and everything checks
out. That proves **integrity** (nobody corrupted it in transit), not **provenance**
(it came from who it claims).

So the honest output is three states, not two:

| state | meaning |
|---|---|
| `INTACT + PROVEN` | signature valid against a key obtained through a separate channel |
| `INTACT, ORIGIN NOT PROVEN` | signature self-consistent; the key came from the file itself |
| `BROKEN` | does not verify |

Reporting the middle state as "verified" is the most common way these tools mislead. Make
the exit code reflect it too — a script that only checks for exit 0 will otherwise believe
the origin was proven.

## What a verifier must never do

**Silently ignore what it cannot re-derive.** If the verifier recomputes four fields out of
seven and returns `VALID`, the other three are unsigned in practice. A real case returned
`VALID` on a bundle carrying `"certified_by": "<an official body>"` that nothing had
checked — and, inside the certificate, the very sentence a human reads and the flag that
triggers the "this is not a reliable bound" warning were both outside the comparison.

Every field that is re-derived must be **compared**. Every field that is not re-derived
must be **rejected**.

## The regression test you must add

Not optional. It is three lines and it is the only thing that keeps the hole closed:

```python
def test_extra_field_is_rejected():
    """Adding any field to a valid record must be refused, at every level."""
    for path in (record, record["certificate"], record["evidence"][0]):
        tampered = deepcopy(record)
        # navigate to `path` in the copy, then:
        tampered_at_path["_note"] = "acceptance-level, risk <= 0.5%"
        assert verify(tampered) is not VALID
```

Also test that two records differing **only** by an extra key do not share a valid
signature. In one real case they did.

## A worked reference implementation

`acta-verificador` (Apache-2.0) implements all four checks and can be read end to end. Its
`ejemplo/` ships a signed record and its key: change one digit and it must refuse. It
returns `--json` and exit codes `0/1/2/3`, where **2 is "intact but origin not proven"** —
the state most tools report as "verified".

Its README is worth reading for what it declines to claim: a signed chain does not protect
against whoever produced it (that is what an RFC 3161 timestamp is for), and it says so
rather than implying otherwise.

## Why this keeps happening

Because the excluded field always has a good reason. Someone needs a place for comments, or
for a client-specific tag, or for a debugging note, and excluding it from the hash is the
obvious way to let it change freely. The reasoning is sound and the result is a channel for
unsigned text that reads as signed.

When you see a blocklist in a signing path, that is not a style preference. That is the bug.
