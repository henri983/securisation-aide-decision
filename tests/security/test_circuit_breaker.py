"""
Tests de sécurité du disjoncteur décisionnel (Circuit Breaker).
"""

import pytest
from src.decision.circuit_breaker import DecisionCircuitBreaker
from src.models.decision import CircuitBreakerStatus


@pytest.mark.security
def test_circuit_breaker_nominal_pass(circuit_breaker: DecisionCircuitBreaker):
    """En l'absence de menace et avec une confiance suffisante, le disjoncteur reste NOMINAL."""
    act, status, fallback, warnings = circuit_breaker.check_and_safeguard(
        nominal_action="APPROVE_STRATEGIC_EXPANSION",
        confidence_score=0.85,
        proactive_threat_detected=False,
        threat_reasons=[],
    )
    assert act == "APPROVE_STRATEGIC_EXPANSION"
    assert status == CircuitBreakerStatus.NOMINAL
    assert fallback is False
    assert len(warnings) == 0


@pytest.mark.security
def test_circuit_breaker_trips_on_proactive_threat(circuit_breaker: DecisionCircuitBreaker):
    """La détection d'une menace proactive déclenche immédiatement le disjoncteur de sécurité."""
    reasons = ["Empoisonnement détecté sur revenue_growth"]
    act, status, fallback, warnings = circuit_breaker.check_and_safeguard(
        nominal_action="APPROVE_STRATEGIC_EXPANSION",
        confidence_score=0.90,
        proactive_threat_detected=True,
        threat_reasons=reasons,
    )
    assert act == "SAFE_FALLBACK_MANUAL_REVIEW_REQUIRED"
    assert status == CircuitBreakerStatus.TRIGGERED_SAFE_FALLBACK
    assert fallback is True
    assert circuit_breaker.trip_count == 1
    assert any("Disjoncteur déclenché" in w for w in warnings)


@pytest.mark.security
def test_circuit_breaker_trips_on_low_confidence(circuit_breaker: DecisionCircuitBreaker):
    """Une confiance inférieure au seuil de sécurité enclenche le repli manuel."""
    act, status, fallback, warnings = circuit_breaker.check_and_safeguard(
        nominal_action="APPROVE_STRATEGIC_EXPANSION",
        confidence_score=0.50,  # Seuil minimal = 0.65
        proactive_threat_detected=False,
        threat_reasons=[],
    )
    assert act == "SAFE_FALLBACK_MANUAL_REVIEW_REQUIRED"
    assert fallback is True
    assert any("Confiance insuffisante" in w for w in warnings)
