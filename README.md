# CredentialAttest — schema-validated, consensus-verified credential attestation

A GenLayer Intelligent Contract primitive that attests a structured credential is **both well-formed and internally consistent**. Anyone submits a credential as JSON; the contract runs a deterministic structural check, then an equivalence-checked semantic consistency check, and stores the verdict.

## Why it exists

Sybil-resistant identity, reputation portability, and credential validation all need the same primitive: an on-chain record that a credential is valid, without trusting the submitter or a single judge. CredentialAttest provides that. It is a building block other contracts and apps can call, not a standalone product.

## Deployed

- **Network:** GenLayer Bradbury Testnet (chain 4221)
- **Contract:** `0xe8CfEB4663874adbee60eDecFe13FB20340eC4F5`
- **Explorer:** https://explorer-bradbury.genlayer.com/address/0xe8CfEB4663874adbee60eDecFe13FB20340eC4F5

## How consensus works

Two independent checks produce the stored verdict. Validators compare the **final verdict**, not their reasoning — per-dimension agreement on prose is not consensus.

**1. Deterministic structural gate (runs first, cheap, unambiguous).**
Every validator computes this identically: the input parses as JSON, carries every required field for its declared type (`employment`, `education`, `certification`, `identity`), each required field is non-empty, the `expires_at` is parseable ISO-8601 and in the future, and the `signature` is well-formed `0x`-prefixed hex. A credential failing any rule is **rejected immediately**, before any semantic round — so the LLM never judges a malformed document and cannot gate an outcome on prose alone.

**2. Semantic consistency check (`gl.eq_principle.prompt_comparative`).**
Only structurally valid credentials proceed. Validators judge whether the credential's own fields cohere — does the subject match what the issuer asserts, do the role/degree fields agree, is there no internal contradiction. Bounded **strictly to the submitted document**: no web access, no outside knowledge. This is the part a machine cannot check but a consensus of LLM judges can.

The verdict stored is structured: `is_valid`, `failed_rule` (empty if none), and `consistency`. The model's raw reply is normalized to the allowed vocabulary (`CONSISTENT` / `INCONSISTENT` / `INCONCLUSIVE`) and never trusted verbatim.

## API

| Method | Type | Description |
|---|---|---|
| `attest_credential(credential_json)` | write | Validate and commit a credential. Returns credential ID. |
| `get_credential(cred_id)` | view | Read a stored credential: validity, failed rule, consistency, attester, timestamps. |
| `total_credentials()` | view | Counter. |
| `supported_types()` | view | Comma-separated list of supported credential types. |

## Verified on-chain

- Valid employment credential (subject "Ada Lovelace", issuer "Analytical Engines Ltd") → consensus-committed with `is_valid: true`, `consistency: CONSISTENT`, `failed_rule: ''`. Both checks passed.
- Expired credential (expires 2021) → **reverted**, nothing stored (`total_credentials` stayed at 1). The deterministic gate rejected it before any semantic round.

Both records are readable on the explorer.

## Why this is reusable

The deterministic-gate-then-equivalence-check pattern is the shape any "validate a submitted document" primitive needs. The schema map is data, so extending to new credential types is a one-line change. The structural gate is the safety property that keeps an LLM from ever deciding an outcome on its own.

## Tests

23 direct-mode tests via `gltest`:

```bash
gltest tests/ -v
```

Coverage: each supported type validates against its own required fields, non-JSON rejection, unknown-type rejection, missing/empty field rejection, expired and unparseable expiry rejection, malformed and short signature rejection, LLM reply normalization (clean / lowercase / off-vocabulary / missing field), consistency-driven validity, ID incrementing, unknown-record handling, attester recording.

The tests were bite-checked — each guard was verified to fail when its defect is reintroduced:

| Defect injected | Tests that fail |
|---|---|
| Expiry check removed | 3 |
| Signature check removed | 2 |
| Required-field check removed | 3 |
| LLM reply not normalized | 1 |
| `is_valid` ignores consistency | 4 |
| Unknown-type check removed | 1 |

Rejection tests register an LLM mock and assert the specific structural rule (or that no stray `KeyError` fired), so they cannot pass on an unrelated error — the blind spot that makes a rejection test fake.

Note: `gl.eq_principle.prompt_comparative`'s internal leader/validator round is proven live on Bradbury (MAJORITY_AGREE below); direct mode cannot simulate that primitive's round, so the tests pin the deterministic gate and the normalization invariant instead.

## Tech Stack

- **Contract:** Python GenLayer Intelligent Contract (GenVM runner `1jb45aa8...`)
- **Storage:** `TreeMap[str, Credential]`, `u256` counter
- **Deterministic check:** pure-Python schema/expiry/signature validation
- **Consensus:** `gl.eq_principle.prompt_comparative` on the final consistency verdict
- **LLM:** `gl.nondet.exec_prompt` with `response_format="json"`, normalized to a fixed vocabulary
- **Network:** GenLayer Bradbury Testnet (chain 4221)
- **No web access** — the semantic check is bounded to the submitted document, so there is no network dependency to break.

## Repository

https://github.com/Adebisi1111/credentialattest

## License

MIT
