# signature-coverage-audit

An agent skill for auditing **what a signature actually covers**.

Not "is the crypto strong" — it usually is. The defect this skill looks for is that
**something readable sits outside what was signed**, so an attacker can write text a human
or a program reads as verified without touching a signed byte.

It was found in **three independent systems on the same day**, written by different people
at different times, and each instance had a slightly different shape:

- a record excluded `_`-prefixed keys from the hash "for annotations" — so an extra key
  could be added to a legitimately signed record and it still reported *verified*; two
  records differing only by that key shared a valid signature;
- an envelope signed its `payload` but consumers read a sibling field, which any
  intermediary could write;
- a verifier **silently ignored** every field it did not re-derive, so a bundle carrying
  `"certified_by": "<an official body>"` came back `VALID`.

The skill is four checks and one mandatory regression test. It needs no API key, no
account, and no network.

## Install

```
hermes skills install <this repo>
```

Or copy `SKILL.md` into your agent's skills directory. It is a single file.

## Reference implementation

`acta-verificador` (Apache-2.0) implements all four checks and can be read end to end.
Verified behaviour of its bundled example:

| input | output | exit |
|---|---|---|
| `ejemplo/acta-demo.json` as shipped | `CADENA ÍNTEGRA · PROCEDENCIA NO PROBADA` | `2` |
| same file, one digit changed | `ACTA NO VERIFICADA` | `1` |

Exit code **2 is the state most tools report as "verified"**: internally consistent, but
the public key came from inside the signed file, so it proves integrity and not origin.
Reporting that as verified is the most common way these tools mislead — and a script that
only checks for exit 0 would believe the origin had been proven.

## Licence

Apache-2.0, same as the reference implementation.
