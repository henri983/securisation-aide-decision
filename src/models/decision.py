"""
Modèles liés aux requêtes et résultats d'aide à la décision.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class CircuitBreakerStatus(str, Enum):
    NOMINAL = "nominal"
    TRIGGERED_SAFE_FALLBACK = "triggered_safe_fallback"


class EvaluateDecisionRequest(BaseModel):
    decision_context_id: str = Field(..., examples=["CTX-ALLOCATION-BUDGET-01"])
    dataset_batch_id: str = Field(..., examples=["BATCH-2026-Q4-01"])
    input_parameters: Dict[str, float] = Field(
        ...,
        examples=[{"revenue_growth": 0.12, "operational_risk": 0.25, "solvency_ratio": 1.85}],
    )
    requestor_id: str = Field(..., examples=["OFFICER-DUPONT"])


class DecisionReport(BaseModel):
    decision_id: str
    decision_context_id: str
    recommended_action: str
    confidence_score: float
    circuit_breaker_status: CircuitBreakerStatus
    feature_contributions: Dict[str, float]
    provenance_hash: str
    decision_signature: str
    evaluated_at: float
    fallback_applied: bool = False
    warning_messages: List[str] = []
