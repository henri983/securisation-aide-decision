"""
Contrôle d'accès basé sur les rôles (RBAC) pour les plateformes d'aide à la décision.
"""

from enum import Enum
from typing import Dict, Set


class DecisionRole(str, Enum):
    CHIEF_DECISION_OFFICER = "cdo"          # Validation et exécution des décisions stratégiques
    DATA_ENGINEER = "data_engineer"         # Ingestion de jeux de données et gestion pipelines
    RISK_AUDITOR = "risk_auditor"           # Audit des alertes IA, de la traçabilité et disjoncteurs
    READONLY_OBSERVER = "observer"          # Consultation des métriques et recommandations en lecture seule


class DecisionPermission(str, Enum):
    INGEST_DATASET = "ingest_dataset"
    TRIGGER_DECISION = "trigger_decision"
    OVERRIDE_CIRCUIT_BREAKER = "override_circuit_breaker"
    VIEW_DECISIONS = "view_decisions"
    VIEW_AUDIT_LOGS = "view_audit_logs"


ROLE_PERMISSIONS: Dict[DecisionRole, Set[DecisionPermission]] = {
    DecisionRole.CHIEF_DECISION_OFFICER: {
        DecisionPermission.TRIGGER_DECISION,
        DecisionPermission.OVERRIDE_CIRCUIT_BREAKER,
        DecisionPermission.VIEW_DECISIONS,
        DecisionPermission.VIEW_AUDIT_LOGS,
    },
    DecisionRole.DATA_ENGINEER: {
        DecisionPermission.INGEST_DATASET,
        DecisionPermission.VIEW_DECISIONS,
    },
    DecisionRole.RISK_AUDITOR: {
        DecisionPermission.VIEW_DECISIONS,
        DecisionPermission.VIEW_AUDIT_LOGS,
    },
    DecisionRole.READONLY_OBSERVER: {
        DecisionPermission.VIEW_DECISIONS,
    },
}


class DecisionSecurityGuard:
    @staticmethod
    def has_permission(role: DecisionRole, permission: DecisionPermission) -> bool:
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms
