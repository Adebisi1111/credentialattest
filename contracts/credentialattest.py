# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""CredentialAttest — issuer-committed, consensus-verified credential attestation.

Well-formed + internally consistent + issued by a party who registered a
keccak256 commitment to its content. (1) deterministic structural gate rejects
before any LLM; (2) issuer keccak256 commitment, registered and staked (binds
issuer to content without on-chain ECDSA recovery, which GenVM lacks);
(3) field-coherence consensus (prompt_comparative), document only.
"""

import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *

REQUIRED_FIELDS = {
    "employment": ["subject", "role", "issuer", "issued_at", "expires_at", "signature"],
    "education": ["subject", "degree", "institution", "issued_at", "signature"],
    "certification": ["subject", "certification", "authority", "issued_at", "expires_at", "signature"],
    "identity": ["subject", "full_name", "issuer", "issued_at", "signature"],
}

ISSUER_STAKE = u256(1) * u256(10) ** u256(18)


@allow_storage
@dataclass
class Issuer:
    address: str
    stake: u256
    active: bool


@allow_storage
@dataclass
class Credential:
    cred_id: str
    cred_type: str
    subject: str
    issuer: str
    commitment: str
    is_valid: bool
    failed_rule: str
    consistency: str
    attester: str


def _is_hex_signature(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{64,}", value) is not None


def _parse_iso(value):
    if not isinstance(value, str):
        return None
    try:
        p = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
    return p if p.tzinfo else p.replace(tzinfo=timezone.utc)


def _is_nonempty_str(value) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def _canonical_content(cred: dict) -> str:
    """Canonical JSON of substantive fields (no signature), sort_keys."""
    content = {k: v for k, v in cred.items() if k != "signature"}
    return json.dumps(content, sort_keys=True, separators=(",", ":"))


def _content_commitment(cred: dict) -> str:
    return Keccak256(_canonical_content(cred).encode("utf-8")).hexdigest()


def _deterministic_check(cred: dict) -> dict:
    """Structural validation; identical every validator. Returns
    {"valid": bool, "failed_rule": str}."""
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

    if _parse_iso(cred.get("issued_at")) is None:
        return {"valid": False, "failed_rule": "issued_at_unparseable"}

    exp = _parse_iso(cred.get("expires_at"))
    if "expires_at" in cred and (exp is None or exp <= datetime.now(timezone.utc)):
        return {"valid": False, "failed_rule": "expired_or_unparseable"}

    if not _is_hex_signature(cred.get("signature")):
        return {"valid": False, "failed_rule": "malformed_signature"}

    return {"valid": True, "failed_rule": ""}


def _judge_consistency(cred: dict):
    """Semantic consistency under equivalence consensus; bounded to the
    document, no network."""
    summary = json.dumps({k: v for k, v in cred.items() if k != "signature"}, indent=2)

    def get_judgement() -> dict:
        prompt = (
            "Are this credential's own fields internally consistent (subject, "
            "issuer, role/degree cohere, no contradiction)? Judge the document "
            'alone, no outside knowledge. Respond as JSON: '
            '{"consistency": "CONSISTENT"|"INCONSISTENT"}\n\n'
            "Credential:\n" + summary
        )
        res = gl.nondet.exec_prompt(prompt, response_format="json")
        verdict = (res.get("consistency") or "").strip().upper()
        if verdict not in ("CONSISTENT", "INCONSISTENT"):
            verdict = "INCONCLUSIVE"
        return {"consistency": verdict}

    principle = (
        "Validators must independently judge whether the fields are internally "
        "consistent, from the document alone, and reach the same conclusion."
    )
    return gl.eq_principle.prompt_comparative(get_judgement, principle)


class CredentialAttest(gl.Contract):
    credentials: TreeMap[str, Credential]
    issuers: TreeMap[str, Issuer]
    commitments: TreeMap[str, str]
    cred_count: u256 = u256(0)

    def __init__(self):
        self.cred_count = u256(0)

    def _addr_key(self, addr) -> str:
        if hasattr(addr, "as_hex"):
            return addr.as_hex.lower()
        return str(addr).lower()

    @gl.public.write.payable
    def register_issuer(self) -> None:
        """Register the caller as an issuer, locking a stake."""
        sender = self._addr_key(gl.message.sender_address)
        if sender in self.issuers:
            raise gl.vm.UserError("Issuer already registered")
        value = gl.message.value
        if value < ISSUER_STAKE:
            raise gl.vm.UserError("Stake below required minimum")
        self.issuers[sender] = Issuer(address=sender, stake=u256(value), active=True)

    @gl.public.view
    def is_registered_issuer(self, address: str) -> bool:
        return self._addr_key(address) in self.issuers

    @gl.public.write
    def register_commitment(self, credential_json: str) -> None:
        """Register a keccak256 commitment to canonical content (issuer only)."""
        sender = self._addr_key(gl.message.sender_address)
        if sender not in self.issuers:
            raise gl.vm.UserError("Caller is not a registered issuer")
        try:
            cred = json.loads(credential_json)
        except Exception:
            raise gl.vm.UserError("Credential is not valid JSON")
        commitment = _content_commitment(cred)
        self.commitments[sender + "|" + commitment] = "1"

    @gl.public.write
    def attest_credential(self, credential_json: str) -> str:
        """Attest a credential: structural gate, issuer commitment, then
        semantic consistency round."""
        try:
            cred = json.loads(credential_json)
        except Exception:
            raise gl.vm.UserError("Credential is not valid JSON")

        structural = _deterministic_check(cred)
        if not structural["valid"]:
            raise gl.vm.UserError(
                "Credential failed structural validation: " + structural["failed_rule"]
            )

        cred_type = cred.get("type", "")
        issuer_field = {"employment": "issuer", "education": "institution",
                        "certification": "authority", "identity": "issuer"}[cred_type]
        issuer_addr = cred.get(issuer_field, "")
        issuer_key = self._addr_key(issuer_addr)
        if issuer_key not in self.issuers:
            raise gl.vm.UserError("Issuer is not registered")

        commitment = _content_commitment(cred)
        if self.commitments.get(issuer_key + "|" + commitment, None) is None:
            raise gl.vm.UserError("Issuer has not registered a commitment to this content")

        try:
            judgement = _judge_consistency(cred)
            consistency = judgement.get("consistency", "INCONCLUSIVE")
        except gl.vm.UserError:
            consistency = "INCONCLUSIVE"

        cred_id = str(int(self.cred_count))
        self.cred_count += u256(1)

        is_valid = consistency == "CONSISTENT"
        failed_rule = ""
        if consistency == "INCONSISTENT":
            failed_rule = "inconsistent_fields"
        elif consistency == "INCONCLUSIVE":
            failed_rule = "consistency_indeterminate"

        self.credentials[cred_id] = Credential(
            cred_id=cred_id,
            cred_type=cred.get("type", ""),
            subject=cred.get("subject", ""),
            issuer=issuer_addr,
            commitment=commitment,
            is_valid=bool(is_valid),
            failed_rule=failed_rule,
            consistency=consistency,
            attester=str(gl.message.sender_address),
        )
        return cred_id

    @gl.public.view
    def get_credential(self, cred_id: str) -> dict:
        c = self.credentials.get(str(cred_id), None)
        if c is None:
            return {"exists": False}
        return {
            "exists": True, "cred_id": c.cred_id, "cred_type": c.cred_type,
            "subject": c.subject, "issuer": c.issuer, "commitment": c.commitment,
            "is_valid": c.is_valid, "failed_rule": c.failed_rule,
            "consistency": c.consistency, "attester": c.attester,
        }

    @gl.public.view
    def total_credentials(self) -> u256:
        return self.cred_count

    @gl.public.view
    def supported_types(self) -> str:
        return ",".join(sorted(REQUIRED_FIELDS.keys()))
