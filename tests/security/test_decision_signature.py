"""
Tests de sécurité de la signature cryptographique des décisions.
"""

import pytest
from src.security.signature import DecisionSignatureService


@pytest.mark.security
def test_decision_signature_verification(signature_service: DecisionSignatureService):
    """Vérifie la validité de la signature HMAC d'une décision."""
    dec_id = "DEC-001"
    prov_hash = "abcdef123456" * 5
    action = "APPROVE"
    confidence = 0.90

    sig = signature_service.sign_decision(dec_id, prov_hash, action, confidence)
    assert signature_service.verify_decision_signature(dec_id, prov_hash, action, confidence, sig) is True

    # Altération de l'action recommandée
    assert signature_service.verify_decision_signature(dec_id, prov_hash, "REJECT", confidence, sig) is False


@pytest.mark.security
def test_decision_signature_tampered_id_fails(signature_service: DecisionSignatureService):
    """Vérifie que changer l'ID de décision invalide la signature."""
    dec_id = "DEC-002"
    prov_hash = "123456abcdef" * 5
    action = "HOLD"
    confidence = 0.80

    sig = signature_service.sign_decision(dec_id, prov_hash, action, confidence)
    assert signature_service.verify_decision_signature("DEC-OTHER", prov_hash, action, confidence, sig) is False
