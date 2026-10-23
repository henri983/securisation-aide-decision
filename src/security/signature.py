"""
Signature cryptographique de scellement des rapports décisionnels.
"""

import hashlib
import hmac
import json
from typing import Any, Dict


class DecisionSignatureService:
    """Service de signature HMAC-SHA256 garantissant la non-répudiation des décisions."""

    def __init__(self, signature_key_hex: str) -> None:
        self.signature_key = bytes.fromhex(signature_key_hex)

    def sign_decision(self, decision_id: str, provenance_hash: str, action: str, confidence: float) -> str:
        """Scelle une décision stratégique par signature HMAC."""
        payload = f"{decision_id}:{provenance_hash}:{action}:{confidence:.2f}"
        return hmac.new(self.signature_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_decision_signature(
        self, decision_id: str, provenance_hash: str, action: str, confidence: float, signature: str
    ) -> bool:
        """Vérifie l'intégrité et l'authenticité de la décision scellée."""
        expected = self.sign_decision(decision_id, provenance_hash, action, confidence)
        return hmac.compare_digest(expected, signature)
