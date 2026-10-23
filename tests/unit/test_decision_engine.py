"""
Tests unitaires du moteur décisionnel multi-critères.
"""

import pytest
from src.decision.decision_engine import MultiCriteriaDecisionEngine


@pytest.mark.unit
def test_expansion_decision_evaluation(decision_engine: MultiCriteriaDecisionEngine):
    """Indicateurs forts (croissance forte, solvabilité élevée, risque modéré) -> EXPANSION."""
    features = {
        "revenue_growth": 0.30,   # 0.30 * 0.40 = 0.12
        "solvency_ratio": 2.50,   # 2.50 * 0.35 = 0.875
        "operational_risk": 0.15, # 0.15 * -0.25 = -0.0375
    }
    action, confidence, contributions = decision_engine.evaluate(features)

    assert action == "APPROVE_STRATEGIC_EXPANSION"
    assert confidence >= 0.70
    assert contributions["revenue_growth"] > 0
    assert contributions["operational_risk"] < 0


@pytest.mark.unit
def test_conservative_capital_preservation(decision_engine: MultiCriteriaDecisionEngine):
    """Indicateurs dégradés (croissance négative, faible solvabilité, risque élevé) -> PRESERVATION."""
    features = {
        "revenue_growth": -0.10,
        "solvency_ratio": 0.80,
        "operational_risk": 0.50,
    }
    action, confidence, contributions = decision_engine.evaluate(features)

    assert action == "CONSERVATIVE_CAPITAL_PRESERVATION"
    assert confidence >= 0.80
