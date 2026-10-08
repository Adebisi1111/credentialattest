"""CredentialAttest direct-mode tests.

Uses gltest direct VM: deploys the contract in-process, drives it as leader,
mocks the LLM for the semantic consistency round.
"""

import json
import pytest

CONTRACT = "contracts/credentialattest.py"

SIG = "0x" + "a1b2c3d4" * 8
# The gltest direct VM derives alice's on-chain address (distinct from her raw
# key bytes); this is the address the contract stores as sender/issuer.
ISSUER = "0xdc18aa3db8bc91a6e390a35e7d0811246ff3ab01"


def _cred(**overrides):
    """A structurally valid employment credential issued by ISSUER."""
    base = {
        "type": "employment",
        "subject": "Ada Lovelace",
        "role": "Senior Engineer",
        "issuer": ISSUER,
        "issued_at": "2026-01-15",
        "expires_at": "2099-01-15",
        "signature": SIG,
    }
    base.update(overrides)
    return json.dumps(base)


_vm = None
_alice = None


@pytest.fixture(autouse=True)
def _bind_fixtures(direct_vm, direct_alice):
    global _vm, _alice
    _vm = direct_vm
    _alice = direct_alice
    yield


@pytest.fixture
def contract(direct_deploy):
    with _vm.prank(_alice):
        return direct_deploy(CONTRACT)


def _mock_consistent():
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "CONSISTENT"}))


def _mock_inconsistent():
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "INCONSISTENT"}))


def _register_issuer(contract):
    _vm.value = 10 ** 18
    contract.register_issuer()
    _vm.value = 0


def _assert_structural_reject(contract, cred_json, expect_rule=None):
    """Assert rejection by the DETERMINISTIC gate specifically. An LLM mock is
    registered and the issuer is set up, so the only thing that can raise is
    the structural gate — not a missing mock or unregistered issuer. For valid
    JSON the commitment is also registered, so the commitment check cannot be
    the thing that rejects."""
    _mock_consistent()
    _register_issuer(contract)
    try:
        json.loads(cred_json)
        contract.register_commitment(cred_json)
    except Exception:
        pass  # invalid JSON can't have a commitment; the JSON gate rejects first
    with pytest.raises(Exception) as excinfo:
        contract.attest_credential(cred_json)
    msg = str(excinfo.value)
    if expect_rule is not None:
        assert expect_rule in msg, f"expected {expect_rule!r}, got: {msg[:200]}"
    else:
        assert "KeyError" not in msg, f"rejected by KeyError, not the gate: {msg[:200]}"
    assert contract.total_credentials() == 0


# ---------------------------------------------------------------------------
# Issuer registration
# ---------------------------------------------------------------------------

def test_register_issuer(contract):
    _vm.value = 10 ** 18
    contract.register_issuer()
    assert contract.is_registered_issuer(ISSUER) is True


def test_register_issuer_rejects_insufficient_stake(contract):
    _vm.value = 10 ** 17
    with pytest.raises(Exception):
        contract.register_issuer()


def test_register_issuer_rejects_double_registration(contract):
    _vm.value = 10 ** 18
    contract.register_issuer()
    with pytest.raises(Exception):
        contract.register_issuer()


# ---------------------------------------------------------------------------
# Commitment check (issuer accountability)
# ---------------------------------------------------------------------------

def test_attest_rejects_unregistered_issuer(contract):
    """A credential naming an issuer who never registered must be rejected.
    Assert the outcome (rejected, nothing stored), not which guard fired —
    an unregistered issuer is stopped by the registration check or, failing
    that, the commitment check; both are correct."""
    _mock_consistent()
    bad = _cred(issuer="0x000000000000000000000000000000000000dEaD")
    with pytest.raises(Exception):
        contract.attest_credential(bad)
    assert contract.total_credentials() == 0


def test_attest_rejects_uncommitted_content(contract):
    _mock_consistent()
    _register_issuer(contract)
    with pytest.raises(Exception) as e:
        contract.attest_credential(_cred())
    assert "commitment" in str(e.value)


def test_attest_rejects_tampered_content(contract):
    _mock_consistent()
    _register_issuer(contract)
    contract.register_commitment(_cred())
    tampered = _cred(role="Chief Wizard")
    with pytest.raises(Exception) as e:
        contract.attest_credential(tampered)
    assert "commitment" in str(e.value)
    assert contract.total_credentials() == 0


def test_register_commitment_rejects_non_issuer(contract):
    with pytest.raises(Exception):
        contract.register_commitment(_cred())


# ---------------------------------------------------------------------------
# Full happy path
# ---------------------------------------------------------------------------

def test_valid_credential_attested(contract):
    _mock_consistent()
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["exists"] is True
    assert c["is_valid"] is True
    assert c["consistency"] == "CONSISTENT"
    assert c["failed_rule"] == ""
    assert c["issuer"] == ISSUER
    # A real keccak256 commitment is stored (64 hex chars, no 0x prefix — that
    # is what Keccak256(...).hexdigest() returns on-chain).
    assert len(c["commitment"]) == 64
    assert all(ch in "0123456789abcdef" for ch in c["commitment"])


# ---------------------------------------------------------------------------
# Deterministic structural gate
# ---------------------------------------------------------------------------

def test_rejects_non_json(contract):
    _assert_structural_reject(contract, "not json")


def test_rejects_unknown_type(contract):
    _assert_structural_reject(contract, _cred(type="driver_license"), expect_rule="unknown_type")


def test_rejects_missing_required_field(contract):
    cred = json.loads(_cred())
    del cred["role"]
    _assert_structural_reject(contract, json.dumps(cred), expect_rule="missing_field_role")


def test_rejects_empty_field(contract):
    _assert_structural_reject(contract, _cred(subject="   "), expect_rule="empty_field_subject")


def test_rejects_expired(contract):
    _assert_structural_reject(contract, _cred(expires_at="2021-01-01"), expect_rule="expired_or_unparseable")


def test_rejects_unparseable_expiry(contract):
    _assert_structural_reject(contract, _cred(expires_at="next tuesday"), expect_rule="expired_or_unparseable")


def test_rejects_unparseable_issued_at(contract):
    _assert_structural_reject(contract, _cred(issued_at="whenever"), expect_rule="issued_at_unparseable")


def test_rejects_malformed_signature(contract):
    _assert_structural_reject(contract, _cred(signature="nope"), expect_rule="malformed_signature")


def test_rejects_short_signature(contract):
    _assert_structural_reject(contract, _cred(signature="0xabc"), expect_rule="malformed_signature")


# ---------------------------------------------------------------------------
# Each supported type
# ---------------------------------------------------------------------------

def _attest_type(contract, cred_json):
    _mock_consistent()
    _register_issuer(contract)
    contract.register_commitment(cred_json)
    contract.attest_credential(cred_json)


def test_education_type(contract):
    c = json.dumps({"type": "education", "subject": "Grace Hopper",
                    "degree": "PhD", "institution": ISSUER,
                    "issued_at": "2026-01-01", "signature": SIG})
    _attest_type(contract, c)
    assert contract.get_credential("0")["is_valid"] is True


def test_certification_type(contract):
    c = json.dumps({"type": "certification", "subject": "Alan Turing",
                    "certification": "Crypto", "authority": ISSUER,
                    "issued_at": "2026-01-01", "expires_at": "2099-01-01",
                    "signature": SIG})
    _attest_type(contract, c)
    assert contract.get_credential("0")["is_valid"] is True


def test_identity_type(contract):
    c = json.dumps({"type": "identity", "subject": "user-42",
                    "full_name": "Katherine Johnson", "issuer": ISSUER,
                    "issued_at": "2026-01-01", "signature": SIG})
    _attest_type(contract, c)
    assert contract.get_credential("0")["is_valid"] is True


# ---------------------------------------------------------------------------
# Semantic consistency
# ---------------------------------------------------------------------------

def test_inconsistent_marked_invalid(contract):
    _mock_inconsistent()
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["is_valid"] is False
    assert c["consistency"] == "INCONSISTENT"
    assert c["failed_rule"] == "inconsistent_fields"


def test_lowercase_reply_normalized(contract):
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "inconsistent"}))
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "INCONSISTENT"
    assert c["is_valid"] is False


def test_off_vocabulary_reply_inconclusive(contract):
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "looks fine to me"}))
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "INCONCLUSIVE"
    assert c["is_valid"] is False
    assert c["failed_rule"] == "consistency_indeterminate"


def test_missing_field_reply_inconclusive(contract):
    _vm.mock_llm(r"consistent", json.dumps({"other": "x"}))
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    assert contract.get_credential("0")["consistency"] == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def test_ids_increment(contract):
    _mock_consistent()
    _register_issuer(contract)
    contract.register_commitment(_cred(subject="First"))
    contract.attest_credential(_cred(subject="First"))
    contract.register_commitment(_cred(subject="Second"))
    contract.attest_credential(_cred(subject="Second"))
    assert contract.total_credentials() == 2
    assert contract.get_credential("0")["subject"] == "First"
    assert contract.get_credential("1")["subject"] == "Second"


def test_unknown_credential_not_found(contract):
    assert contract.get_credential("999")["exists"] is False


def test_supported_types(contract):
    assert set(contract.supported_types().split(",")) == {
        "employment", "education", "certification", "identity"}


def test_attester_recorded(contract):
    import re
    _mock_consistent()
    _register_issuer(contract)
    contract.register_commitment(_cred())
    contract.attest_credential(_cred())
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", contract.get_credential("0")["attester"])
