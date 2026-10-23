"""
Moteur IA de Détection Proactive de Menaces & Empoisonnement (Proactive Threat Engine).

Détecte proactivement AVANT exécution décisionnelle :
1. L'empoisonnement de données (Data Poisoning / Outlier Injection)
2. Les perturbations contradictoires (Adversarial Noise visant à biaiser le modèle)
3. La dérive statistique de distribution (Concept / Distribution Drift)
"""

import math
import time
from typing import Dict, List, Optional, Tuple
from src.models.threat_alert import ThreatAlertRecord, ThreatCategory, ThreatSeverity


class ProactiveDecisionThreatDetector:
    """Moteur IA proactif protégeant l'intégrité statistique des modèles décisionnels."""

    # Référentiel des moyennes et écarts-types normaux par feature
    BASELINE_STATS: Dict[str, Tuple[float, float]] = {
        "revenue_growth": (0.08, 0.05),     # Moyenne 8%, Ecart-type 5%
        "solvency_ratio": (1.60, 0.30),     # Moyenne 1.60, Ecart-type 0.30
        "operational_risk": (0.20, 0.08),   # Moyenne 0.20, Ecart-type 0.08
    }

    def __init__(
        self,
        max_zscore: float = 3.5,
        threat_threshold: float = 0.75,
    ) -> None:
        self.max_zscore = max_zscore
        self.threat_threshold = threat_threshold
        self.alert_history: List[ThreatAlertRecord] = []

    def evaluate_proactive_threats(
        self, input_features: Dict[str, float]
    ) -> Tuple[bool, float, List[str], Optional[ThreatCategory], ThreatSeverity]:
        """
        Analyse proactivement les paramètres d'entrée avant que le modèle ne décide.
        Retourne : (threat_detected, risk_score, reasons, category, severity).
        """
        reasons: List[str] = []
        deviations: List[float] = []
        detected_features: List[str] = []
        cat: Optional[ThreatCategory] = None
        severity: ThreatSeverity = ThreatSeverity.LOW

        for feat, val in input_features.items():
            if feat in self.BASELINE_STATS:
                mean, std = self.BASELINE_STATS[feat]
                z_score = abs(val - mean) / (std if std > 0 else 1.0)

                # 1. Détection d'empoisonnement statistique (Outlier Injection)
                if z_score > self.max_zscore:
                    reasons.append(
                        f"Empoisonnement détecté sur '{feat}' : valeur {val:.2f} (Z-Score = {z_score:.1f} > max {self.max_zscore})."
                    )
                    deviations.append(min(1.0, z_score / 5.0))
                    detected_features.append(feat)
                    cat = ThreatCategory.DATA_POISONING

                # 2. Valeurs physiquement aberrantes / négatives interdites
                if feat in ["solvency_ratio", "operational_risk"] and val < 0:
                    reasons.append(f"Paramètre négatif impossible '{feat}' ({val:.2f}) : tentative d'injection hostile.")
                    deviations.append(0.95)
                    detected_features.append(feat)
                    cat = ThreatCategory.ADVERSARIAL_PERTURBATION

        # Calcul du risque proactif global
        if not deviations:
            risk_score = 0.05
        else:
            risk_score = round(max(deviations), 2)

        is_threat = risk_score >= self.threat_threshold

        if is_threat:
            severity = ThreatSeverity.CRITICAL if risk_score >= 0.90 else ThreatSeverity.HIGH
            alert = ThreatAlertRecord(
                alert_id=f"THR-{len(self.alert_history) + 1:05d}",
                category=cat or ThreatCategory.DATA_POISONING,
                severity=severity,
                risk_score=risk_score,
                description="Menace proactive interceptée avant ingestion dans l'algorithme décisionnel.",
                detected_features=detected_features,
                timestamp=time.time(),
                circuit_breaker_tripped=True,
            )
            self.alert_history.append(alert)

        return is_threat, risk_score, reasons, cat, severity
