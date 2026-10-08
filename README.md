# CredentialAttest — issuer-committed, consensus-verified credential attestation

A GenLayer Intelligent Contract primitive that attests a structured credential is **well-formed, internally consistent, AND issued by a party who registered a cryptographic commitment to its content**. Three independent checks produce the stored verdict.

## Why it exists

Sybil-resistant identity, reputation portability, and credential validation all need the same primitive: an on-chain record that a credential is valid *and* attributable to an issuer who has something at stake, without trusting the submitter or a single judge. CredentialAttest provides that. It is a building block other contracts and apps can call, not a standalone product.

## Deployed

- **Network:** GenLayer Bradbury Testnet (chain 4221)
- **Contract:** `0xD96e10391E99D70c5666817DC8Ab0f67A6d7fDd5`
- **Explorer:** https://explorer-bradbury.genlayer.com/address/0xD96e10391E99D70c5666817DC8Ab0f67A6d7fDd5

## How consensus works

Validators compare the **final verdict**, not their reasoning — per-dimension agreement on prose is not consensus.

**1. Deterministic structural gate (runs first, cheap, unambiguous).**
Every validator computes this identically: JSON parses, required fields present and non-empty for the declared type (`employment`, `education`, `certification`, `identity`), `issued_at` and `expires_at` parseable ISO-8601 (expiry in the future), `signature` well-formed hex. A credential failing any rule is **rejected immediately**, before any semantic round — so the LLM never judges a malformed document.

**2. Issuer commitment check (deterministic, on-chain accountability).**
The issuer first calls `register_issuer`, **locking a 1 GEN stake**, then `register_commitment` with a keccak256 over the canonical credential content. `attest_credential` recomputes that keccak256 and requires it to match a commitment the named issuer registered. This binds the issuer to the content: a registered issuer cannot attest arbitrary credentials it did not actually issue, and an unregistered issuer cannot attest at all. The commitment is over canonical JSON (sorted keys, signature excluded) so it is identical on every node.

This is a **commitment scheme**, chosen because GenVM provides no on-chain ECDSA recovery (`ecrecover` is absent from the std lib). Rather than a signature check that cannot be performed on-chain, the issuer's own registered commitment is the proof of authorship, and the locked stake makes registering a commitment costly to abuse. Anyone can independently derive the commitment an issuer must register.

**3. Semantic consistency check (`gl.eq_principle.prompt_comparative`).**
Only credentials passing checks 1 and 2 proceed. Validators judge whether the credential's own fields cohere — does the subject match what the issuer asserts, do the role/degree fields agree, is there no internal contradiction. Bounded **strictly to the submitted document**: no web access, no outside knowledge. The model's reply is normalized to a fixed vocabulary (`CONSISTENT` / `INCONSISTENT` / `INCONCLUSIVE`) and never trusted verbatim.

The stored verdict is structured: `is_valid`, `failed_rule`, `consistency`, the `commitment`, and the attester.

## API

| Method | Type | Description |
|---|---|---|
| `register_issuer()` | write (payable) | Register the caller as an issuer, locking ≥1 GEN stake. |
| `register_commitment(credential_json)` | write | Register a keccak256 commitment to canonical content (issuer only). |
| `attest_credential(credential_json)` | write | Validate and commit a credential. Returns credential ID. |
| `is_registered_issuer(address)` | view | Whether an address is a registered issuer. |
| `get_credential(cred_id)` | view | Read a stored credential: validity, failed rule, consistency, commitment, attester. |
| `total_credentials()` | view | Counter. |
| `supported_types()` | view | Comma-separated supported credential types. |

## Verified on-chain

- **Full happy path:** `register_issuer` (1 GEN) → `register_commitment` → `attest_credential` → committed with `is_valid: true`, `consistency: CONSISTENT`, and a real keccak256 commitment stored.
- **Tampered content** (role changed after commitment) → **rejected**, nothing stored. A registered issuer cannot attest content it did not commit to.
- **Unregistered issuer** → **rejected**, nothing stored.

All records are readable on the explorer.

## Why this is reusable

The deterministic-gate-then-commitment-then-equivalence-check pattern is the shape any "validate an attributed document" primitive needs. The schema map is data, so extending to new credential types is a one-line change. The structural gate is the safety property that keeps an LLM from ever deciding an outcome on its own, and the staked commitment is what makes an attestation mean something.

## Tests

28 direct-mode tests via `gltest`:

```bash
gltest tests/ -v
```

Coverage: issuer registration (stake minimum, double-registration), commitment accountability (unregistered issuer, uncommitted content, tampered content, non-issuer commitment), the full happy path, structural gate (non-JSON, unknown type, missing/empty field, expired/unparseable expiry, unparseable issued_at, malformed/short signature), each supported type, LLM normalization (clean / lowercase / off-vocabulary / missing field), consistency-driven validity, ID incrementing, unknown-record handling, attester recording.

The tests were bite-checked — each guard was verified to fail when its defect is reintroduced:

| Defect injected | Tests that fail |
|---|---|
| Commitment check removed | 2 |
| Stake minimum removed | 1 |
| Expiry check removed | 2 |
| LLM normalization removed | 2 |
| `is_valid` ignores consistency | 3 |
| `issued_at` check removed | 1 |

The issuer-registration check is covered by defense-in-depth: with it removed, an unregistered issuer is still stopped by the commitment check, so the credential is rejected either way — the test asserts that outcome rather than which guard fired.

Note: `gl.eq_principle.prompt_comparative`'s internal leader/validator round is proven live on Bradbury; direct mode cannot simulate that primitive's round, so the tests pin the deterministic gate, the commitment check, and the normalization invariant instead.

## Tech Stack

- **Contract:** Python GenLayer Intelligent Contract (GenVM runner `1jb45aa8...`)
- **Storage:** `TreeMap[str, Credential]`, `TreeMap[str, Issuer]`, `TreeMap[str, str]` commitments, `u256` counter
- **Deterministic checks:** pure-Python schema/expiry/signature validation + keccak256 commitment
- **Consensus:** `gl.eq_principle.prompt_comparative` on the final consistency verdict
- **LLM:** `gl.nondet.exec_prompt` with `response_format="json"`, normalized to a fixed vocabulary
- **Commitment:** `Keccak256(canonical_json).hexdigest()` (importable from `genlayer`)
- **Network:** GenLayer Bradbury Testnet (chain 4221)
- **No web access** — the semantic check is bounded to the submitted document, so there is no network dependency to break.

## Repository

https://github.com/Adebisi1111/credentialattest

## License

MIT
