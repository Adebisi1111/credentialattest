# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""CredentialAttest — schema-validated, consensus-verified credential attestation.

Attests that a structured credential is well-formed AND that its fields
actually cohere. Two independent checks produce the stored verdict.

Deterministic (every validator computes identically): JSON parses, required
fields present and non-empty for the declared type, expiry parseable and in
the future, signature is well-formed hex. Most malformed credentials die
here, cheaply and unambiguously.

Equivalence (gl.eq_principle.prompt_comparative): validators judge whether the
credential's free-text fields are internally consistent. Bounded strictly to
the submitted document — no network dependency.

Validators compare the FINAL VERDICT, not their reasoning. The deterministic
gate runs first and can reject before any semantic check, so no LLM alone
decides an outcome.
"""

import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *

# Required fields per credential type. An unknown type fails immediately.
REQUIRED_FIELDS = {
    "employment": ["subject", "role", "issuer", "issued_at", "expires_at", "signature"],
    "education": ["subject", "degree", "institution", "issued_at", "signature"],
    "certification": ["subject", "certification", "authority", "issued_at", "expires_at", "signature"],
    "identity": ["subject", "full_name", "issuer", "issued_at", "signature"],
}


# ---------------------------------------------------------------------------
# Storage model
# ---------------------------------------------------------------------------


@allow_storage
@dataclass
class Credential:
    cred_id: str
    cred_type: str
    subject: str
    issuer: str
    is_valid: bool
    failed_rule: str
    consistency: str
    attester: str
    created_at: u256
    verify_count: u256
    last_verify_result: str


# ---------------------------------------------------------------------------
# Deterministic validation
# ---------------------------------------------------------------------------


def _is_hex_signature(value) -> bool:
    """0x-prefixed hex of plausible length."""
    if not isinstance(value, str):
        return False
    if not value.startswith("0x"):
        return False
    body = value[2:]
    if len(body) < 32:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in body)


def _is_future_iso8601(value) -> bool:
    """Parseable ISO-8601 and in the future."""
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed > datetime.now(timezone.utc)


def _is_nonempty_str(value) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def _deterministic_check(cred: dict) -> dict:
    """Structural validation. Every validator computes the same verdict.
    Returns {"valid": bool, "failed_rule": str}; rule order is fixed."""
    if not isinstance(cred, dict):
        return {"valid": False, "failed_rule": "not_a_json_object"}

    cred_type = cred.get("type")
    if not _is_nonempty_str(cred_type):
        return {"valid": False, "failed_rule": "missing_type"}
    if cred_type not in REQUIRED_FIELDS:
        return {"valid": False, "failed_rule": "unknown_type"}

    for field in REQUIRED_FIELDS[cred_type]:
        if field not in cred:
            return {"valid": False, "failed_rule": "missing_field_" + field}
        if not _is_nonempty_str(cred[field]):
            return {"valid": False, "failed_rule": "empty_field_" + field}

    if "expires_at" in cred and not _is_future_iso8601(cred["expires_at"]):
        return {"valid": False, "failed_rule": "expired_or_unparseable"}

    if not _is_hex_signature(cred.get("signature")):
        return {"valid": False, "failed_rule": "malformed_signature"}

    return {"valid": True, "failed_rule": ""}


# ---------------------------------------------------------------------------
# Equivalence check
# ---------------------------------------------------------------------------


def _semantic_summary(cred: dict) -> str:
    """Render the credential for the consistency judgement."""
    return json.dumps({k: v for k, v in cred.items() if k != "signature"}, indent=2)


def _judge_consistency(cred: dict):
    """Semantic consistency check under equivalence consensus. Bounded to the
    submitted document — never fetches, never invents outside facts."""
    summary = _semantic_summary(cred)

    def get_judgement() -> dict:
        prompt = (
            "Judge whether this credential's own fields are internally "
            "consistent — do the subject, issuer, and role/degree fields "
            "cohere with no internal contradiction. Judge the document alone; "
            "use no outside knowledge.\n\n"
            'Respond as JSON: {"consistency": "CONSISTENT"|"INCONSISTENT"}\n\n'
            "Credential:\n" + summary
        )
        res = gl.nondet.exec_prompt(prompt, response_format="json")
        verdict = (res.get("consistency") or "").strip().upper()
        if verdict not in ("CONSISTENT", "INCONSISTENT"):
            verdict = "INCONCLUSIVE"
        return {"consistency": verdict}

    principle = (
        "The judgement must agree on whether the credential's fields are "
        "internally consistent. Validators must independently assess the "
        "document and reach the same conclusion, judging the document alone "
        "with no outside knowledge."
    )
    return gl.eq_principle.prompt_comparative(get_judgement, principle)


def _normalize_judgement(raw) -> str:
    """Coerce to allowed vocabulary; never trust the reply verbatim."""
    if not isinstance(raw, str):
        return "INCONCLUSIVE"
    upper = raw.strip().upper()
    if "INCONSISTENT" in upper:
        return "INCONSISTENT"
    if "CONSISTENT" in upper:
        return "CONSISTENT"
    return "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


class CredentialAttest(gl.Contract):
    credentials: TreeMap[str, Credential]
    cred_count: u256 = u256(0)

    def __init__(self):
        self.cred_count = u256(0)

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    @gl.public.write
    def attest_credential(self, credential_json: str) -> str:
        """Attest a credential. The deterministic structural check runs first;
        a credential failing it is rejected before any semantic round, so the
        LLM never judges a malformed document."""
        try:
            cred = json.loads(credential_json)
        except Exception:
            raise gl.vm.UserError("Credential is not valid JSON")

        structural = _deterministic_check(cred)
        if not structural["valid"]:
            raise gl.vm.UserError(
                "Credential failed structural validation: " + structural["failed_rule"]
            )

        try:
            judgement = _judge_consistency(cred)
            consistency = _normalize_judgement(judgement.get("consistency", ""))
        except gl.vm.UserError:
            consistency = "INCONCLUSIVE"

        cred_type = cred.get("type", "")
        subject = cred.get("subject", "")
        issuer = cred.get("issuer", "")

        is_valid = structural["valid"] and consistency == "CONSISTENT"
        failed_rule = structural["failed_rule"]
        if is_valid is False and not failed_rule:
            failed_rule = "inconsistent_fields"

        cred_id = str(int(self.cred_count))
        self.cred_count += u256(1)

        self.credentials[cred_id] = Credential(
            cred_id=cred_id,
            cred_type=cred_type,
            subject=subject,
            issuer=issuer,
            is_valid=bool(is_valid),
            failed_rule=failed_rule,
            consistency=consistency,
            attester=str(gl.message.sender_address),
            created_at=u256(self._now()),
            verify_count=u256(0),
            last_verify_result="",
        )
        return cred_id

    @gl.public.view
    def get_credential(self, cred_id: str) -> dict:
        """Read a stored credential attestation."""
        cred_id = str(cred_id)
        c = self.credentials.get(cred_id, None)
        if c is None:
            return {"exists": False}
        return {
            "exists": True,
            "cred_id": c.cred_id,
            "cred_type": c.cred_type,
            "subject": c.subject,
            "issuer": c.issuer,
            "is_valid": c.is_valid,
            "failed_rule": c.failed_rule,
            "consistency": c.consistency,
            "attester": c.attester,
            "created_at": c.created_at,
            "verify_count": c.verify_count,
            "last_verify_result": c.last_verify_result,
        }

    @gl.public.view
    def total_credentials(self) -> u256:
        return self.cred_count

    @gl.public.view
    def supported_types(self) -> str:
        return ",".join(sorted(REQUIRED_FIELDS.keys()))
