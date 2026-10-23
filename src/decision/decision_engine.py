"""
Moteur décisionnel multi-critères avec estimation de confiance et explicabilité (Feature Attribution).
"""

from typing import Dict, Tuple


class MultiCriteriaDecisionEngine:
    """Moteur décisionnel pondéré évaluant les risques et opportunités stratégiques."""

    DEFAULT_WEIGHTS = {
        "revenue_growth": 0.40,
        "solvency_ratio": 0.35,
        "operational_risk": -0.25,
    }

    def evaluate(
        self, input_features: Dict[str, float]
    ) -> Tuple[str, float, Dict[str, float]]:
        """
        Évalue les indicateurs et produit une recommandation, un score de confiance et les contributions.
        Retourne : (recommended_action, confidence_score, feature_contributions).
        """
        score = 0.0
        contributions: Dict[str, float] = {}

        for feat, val in input_features.items():
            weight = self.DEFAULT_WEIGHTS.get(feat, 0.10)
            contrib = val * weight
            contributions[feat] = round(contrib, 4)
            score += contrib

        # Normalisation du score
        normalized_score = round(score, 3)

        if normalized_score >= 0.50:
            action = "APPROVE_STRATEGIC_EXPANSION"
            confidence = min(0.95, 0.70 + (normalized_score * 0.2))
        elif normalized_score >= 0.20:
            action = "MAINTAIN_CURRENT_TRAJECTORY"
            confidence = 0.85
        else:
            action = "CONSERVATIVE_CAPITAL_PRESERVATION"
            confidence = 0.90

        return action, round(confidence, 2), contributions
