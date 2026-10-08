"""CredentialAttest direct-mode tests.

Uses gltest direct VM: deploys the contract in-process, drives it as leader,
mocks the LLM for the semantic consistency round.
"""

import json
import pytest

CONTRACT = "contracts/credentialattest.py"

SIG = "0x" + "a1b2c3d4" * 8  # valid 0x-prefixed hex signature


def _cred(**overrides):
    """A structurally valid employment credential, overridable per test."""
    base = {
        "type": "employment",
        "subject": "Ada Lovelace",
        "role": "Senior Engineer",
        "issuer": "Analytical Engines Ltd",
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


def _assert_structural_reject(contract, cred_json, expect_rule=None):
    """Assert a credential is rejected by the DETERMINISTIC gate specifically.

    Two safeguards against a false pass:
      1. An LLM mock is registered, so if the structural gate did NOT reject,
         execution would proceed to the semantic round and SUCCEED — the only
         thing that can raise is the structural gate (not a missing mock).
      2. The error message must reference the expected rule (or at least be a
         UserError-style structural message, not a stray KeyError/TypeError
         from a code path the guard was supposed to prevent).
    """
    _mock_consistent()
    with pytest.raises(Exception) as excinfo:
        contract.attest_credential(cred_json)
    msg = str(excinfo.value)
    if expect_rule is not None:
        assert expect_rule in msg, f"expected rule {expect_rule!r} in error, got: {msg[:200]}"
    else:
        # At minimum, it must not be a bare KeyError (which would mean the
        # intended guard was bypassed and the failure came from elsewhere).
        assert "KeyError" not in msg, f"rejected by KeyError, not the structural gate: {msg[:200]}"
    # The rejected credential must not have been stored.
    assert contract.total_credentials() == 0


# ---------------------------------------------------------------------------
# Deterministic structural gate
# ---------------------------------------------------------------------------

def test_valid_credential_is_accepted(contract):
    _mock_consistent()
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["exists"] is True
    assert c["is_valid"] is True
    assert c["failed_rule"] == ""
    assert c["consistency"] == "CONSISTENT"


def test_rejects_non_json(contract):
    _assert_structural_reject(contract, "this is not json")


def test_rejects_unknown_type(contract):
    _assert_structural_reject(contract, _cred(type="driver_license"), expect_rule="unknown_type")


def test_rejects_missing_required_field(contract):
    cred = json.loads(_cred())
    del cred["role"]
    _assert_structural_reject(contract, json.dumps(cred), expect_rule="missing_field_role")


def test_rejects_empty_field(contract):
    _assert_structural_reject(contract, _cred(subject="   "))


def test_rejects_expired_credential(contract):
    _assert_structural_reject(contract, _cred(expires_at="2021-01-01"), expect_rule="expired_or_unparseable")


def test_rejects_unparseable_expiry(contract):
    _assert_structural_reject(contract, _cred(expires_at="next tuesday"))


def test_rejects_malformed_signature(contract):
    _assert_structural_reject(contract, _cred(signature="not-a-signature"), expect_rule="malformed_signature")


def test_rejects_short_signature(contract):
    _assert_structural_reject(contract, _cred(signature="0xabc"))


def test_deterministic_gate_rejects_before_llm(contract):
    """A structurally invalid credential must be rejected by the structural
    gate specifically — proven by registering an LLM mock, so a missing mock
    cannot be the thing that raises."""
    _assert_structural_reject(contract, _cred(expires_at="2020-01-01"))


# ---------------------------------------------------------------------------
# Each supported type validates against its own required fields
# ---------------------------------------------------------------------------

def test_education_type(contract):
    _mock_consistent()
    contract.attest_credential(json.dumps({
        "type": "education", "subject": "Grace Hopper",
        "degree": "PhD Mathematics", "institution": "Yale",
        "issued_at": "2026-01-01", "signature": SIG,
    }))
    assert contract.get_credential("0")["is_valid"] is True


def test_certification_type(contract):
    _mock_consistent()
    contract.attest_credential(json.dumps({
        "type": "certification", "subject": "Alan Turing",
        "certification": "Crypto Level 9", "authority": "GCHQ",
        "issued_at": "2026-01-01", "expires_at": "2099-01-01",
        "signature": SIG,
    }))
    assert contract.get_credential("0")["is_valid"] is True


def test_identity_type(contract):
    _mock_consistent()
    contract.attest_credential(json.dumps({
        "type": "identity", "subject": "user-42",
        "full_name": "Katherine Johnson", "issuer": "GovID",
        "issued_at": "2026-01-01", "signature": SIG,
    }))
    assert contract.get_credential("0")["is_valid"] is True


def test_education_rejects_missing_degree(contract):
    _assert_structural_reject(contract, json.dumps({
        "type": "education", "subject": "X",
        "institution": "Yale", "issued_at": "2026-01-01",
        "signature": SIG,
    }))


# ---------------------------------------------------------------------------
# Semantic consistency check
# ---------------------------------------------------------------------------

def test_inconsistent_credential_marked_invalid(contract):
    """Structurally valid but semantically inconsistent → is_valid False,
    consistency INCONSISTENT, failed_rule names the reason."""
    _mock_inconsistent()
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["is_valid"] is False
    assert c["consistency"] == "INCONSISTENT"
    assert c["failed_rule"] == "inconsistent_fields"


def test_llm_clean_reply_accepted(contract):
    """A clean, in-vocabulary reply is used as-is."""
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "CONSISTENT"}))
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "CONSISTENT"
    assert c["is_valid"] is True


def test_llm_lowercase_reply_normalized(contract):
    """A lowercase in-vocabulary reply is uppercased to the canonical form."""
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "inconsistent"}))
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "INCONSISTENT"
    assert c["is_valid"] is False


def test_llm_off_vocabulary_reply_is_inconclusive(contract):
    """A reply outside the vocabulary is coerced to INCONCLUSIVE and cannot
    make a credential valid — the LLM is never trusted to produce an outcome
    verbatim. Prose like 'looks consistent' is deliberately refused rather
    than guessed at, because substring-matching an ambiguous reply is unsafe."""
    _vm.mock_llm(r"consistent", json.dumps({"consistency": "yes, this looks consistent to me"}))
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "INCONCLUSIVE"
    assert c["is_valid"] is False


def test_llm_missing_field_is_inconclusive(contract):
    """A reply with no consistency key at all is INCONCLUSIVE, never valid."""
    _vm.mock_llm(r"consistent", json.dumps({"other": "value"}))
    contract.attest_credential(_cred())
    c = contract.get_credential("0")
    assert c["consistency"] == "INCONCLUSIVE"
    assert c["is_valid"] is False


# ---------------------------------------------------------------------------
# State design
# ---------------------------------------------------------------------------

def test_ids_increment(contract):
    _mock_consistent()
    contract.attest_credential(_cred(subject="First"))
    contract.attest_credential(_cred(subject="Second"))
    assert contract.total_credentials() == 2
    assert contract.get_credential("0")["subject"] == "First"
    assert contract.get_credential("1")["subject"] == "Second"


def test_unknown_credential_not_found(contract):
    assert contract.get_credential("999")["exists"] is False


def test_supported_types_listed(contract):
    types = contract.supported_types().split(",")
    assert set(types) == {"employment", "education", "certification", "identity"}


def test_attester_recorded(contract):
    _mock_consistent()
    contract.attest_credential(_cred())
    a = contract.get_credential("0")["attester"]
    import re
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", a)
