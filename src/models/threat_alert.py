"""
Modèles d'alertes de menaces et manipulations proactives sur l'aide à la décision.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    DATA_POISONING = "data_poisoning"              # Injection de valeurs aberrantes pour biaiser le modèle
    ADVERSARIAL_PERTURBATION = "adversarial_noise"  # Bruit calculé pour inverser la recommandation
    DISTRIBUTION_DRIFT = "distribution_drift"      # Dérive non surveillée de la distribution des données
    UNAUTHORIZED_OVERRIDE = "unauthorized_override" # Tentative de contourner le disjoncteur de sécurité


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatAlertRecord(BaseModel):
    alert_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    risk_score: float
    description: str
    detected_features: List[str]
    timestamp: float
    circuit_breaker_tripped: bool
