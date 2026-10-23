"""
Disjoncteur de sécurité décisionnelle (Decision Circuit Breaker).
Intercepte les risques de manipulation, d'empoisonnement de données et de faible confiance,
et bascule le système en mode de repli sécurisé (Fail-Safe Conservative Mode).
"""

from typing import Dict, List, Tuple
from src.models.decision import CircuitBreakerStatus


class DecisionCircuitBreaker:
    """Disjoncteur décisionnel empêchant l'exécution d'ordres fondés sur des données altérées."""

    def __init__(self, min_confidence_threshold: float = 0.65) -> None:
        self.min_confidence_threshold = min_confidence_threshold
        self.trip_count = 0

    def check_and_safeguard(
        self,
        nominal_action: str,
        confidence_score: float,
        proactive_threat_detected: bool,
        threat_reasons: List[str],
    ) -> Tuple[str, CircuitBreakerStatus, bool, List[str]]:
        """
        Vérifie si les conditions nominales sont réunies :
        Si une menace proactive est détectée OU si la confiance est trop faible,
        enclenche le repli sécurisé et déclenche le disjoncteur.
        Retourne : (effective_action, status, fallback_applied, warnings).
        """
        warnings: List[str] = []

        if proactive_threat_detected or confidence_score < self.min_confidence_threshold:
            self.trip_count += 1
            if proactive_threat_detected:
                warnings.append("Disjoncteur déclenché : détection proactive d'anomalie ou empoisonnement.")
                warnings.extend(threat_reasons)
            if confidence_score < self.min_confidence_threshold:
                warnings.append(
                    f"Confiance insuffisante ({confidence_score:.2f} < seuil {self.min_confidence_threshold:.2f})."
                )

            # Action de repli déterministe et sûre
            effective_action = "SAFE_FALLBACK_MANUAL_REVIEW_REQUIRED"
            return effective_action, CircuitBreakerStatus.TRIGGERED_SAFE_FALLBACK, True, warnings

        return nominal_action, CircuitBreakerStatus.NOMINAL, False, warnings
