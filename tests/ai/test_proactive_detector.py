"""
Tests du moteur IA de Détection Proactive des Menaces et Empoisonnements.
"""

import pytest
from src.ai.proactive_threat_detector import ProactiveDecisionThreatDetector
from src.models.threat_alert import ThreatCategory, ThreatSeverity


@pytest.mark.ai
def test_proactive_normal_input_within_baseline(proactive_detector: ProactiveDecisionThreatDetector):
    """Paramètres conformes aux distributions statistiques historiques : aucune menace détectée."""
    normal_features = {
        "revenue_growth": 0.09,   # Proche moyenne 0.08
        "solvency_ratio": 1.65,   # Proche moyenne 1.60
        "operational_risk": 0.19, # Proche moyenne 0.20
    }
    is_threat, risk_score, reasons, cat, severity = proactive_detector.evaluate_proactive_threats(normal_features)

    assert is_threat is False
    assert risk_score < 0.30
    assert len(reasons) == 0
    assert cat is None


@pytest.mark.ai
def test_data_poisoning_outlier_detected(proactive_detector: ProactiveDecisionThreatDetector):
    """
    Injection de valeur aberrante (Data Poisoning) :
    Croissance du chiffre d'affaires à 90% (0.90) vs moyenne 8% (écart-type 5%) -> Z-score > 16.
    """
    poisoned_features = {
        "revenue_growth": 0.90,
        "solvency_ratio": 1.60,
        "operational_risk": 0.20,
    }
    is_threat, risk_score, reasons, cat, severity = proactive_detector.evaluate_proactive_threats(poisoned_features)

    assert is_threat is True
    assert risk_score >= 0.75
    assert cat == ThreatCategory.DATA_POISONING
    assert any("Empoisonnement" in r for r in reasons)


@pytest.mark.ai
def test_adversarial_negative_value_injection_detected(proactive_detector: ProactiveDecisionThreatDetector):
    """Tentative d'injection d'un ratio de solvabilité négatif pour inverser la logique du modèle."""
    adversarial_features = {
        "revenue_growth": 0.08,
        "solvency_ratio": -1.50,  # Impossible physiquement
        "operational_risk": 0.20,
    }
    is_threat, risk_score, reasons, cat, severity = proactive_detector.evaluate_proactive_threats(adversarial_features)

    assert is_threat is True
    assert risk_score >= 0.90
    assert cat == ThreatCategory.ADVERSARIAL_PERTURBATION
    assert severity == ThreatSeverity.CRITICAL


@pytest.mark.ai
def test_proactive_alert_history_recording(proactive_detector: ProactiveDecisionThreatDetector):
    """Vérifie l'enregistrement et l'auditabilité des alertes dans l'historique."""
    features = {"revenue_growth": 0.85}
    proactive_detector.evaluate_proactive_threats(features)

    assert len(proactive_detector.alert_history) >= 1
    last_alert = proactive_detector.alert_history[-1]
    assert last_alert.circuit_breaker_tripped is True
    assert "revenue_growth" in last_alert.detected_features
