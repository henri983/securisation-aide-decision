"""
Tests unitaires des permissions RBAC pour la plateforme décisionnelle.
"""

import pytest
from src.security.rbac import DecisionPermission, DecisionRole, DecisionSecurityGuard


@pytest.mark.unit
def test_chief_decision_officer_permissions():
    """Le CDO peut évaluer les décisions et forcer/ajuster les politiques, mais pas ingérer les lots bruts."""
    role = DecisionRole.CHIEF_DECISION_OFFICER
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.TRIGGER_DECISION) is True
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.OVERRIDE_CIRCUIT_BREAKER) is True
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.INGEST_DATASET) is False


@pytest.mark.unit
def test_data_engineer_permissions():
    """Le Data Engineer est habilité à ingérer les données mais pas à déclencher les décisions exécutives."""
    role = DecisionRole.DATA_ENGINEER
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.INGEST_DATASET) is True
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.TRIGGER_DECISION) is False


@pytest.mark.unit
def test_risk_auditor_permissions():
    """L'auditeur de risque consulte les décisions et logs d'audit."""
    role = DecisionRole.RISK_AUDITOR
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.VIEW_AUDIT_LOGS) is True
    assert DecisionSecurityGuard.has_permission(role, DecisionPermission.TRIGGER_DECISION) is False
