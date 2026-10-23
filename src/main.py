"""
Application FastAPI - Sécurisation des Systèmes d'Aide à la Décision (DSS)
avec Détection Proactive des Menaces par IA.
"""

import time
import uuid
from typing import Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.ai.proactive_threat_detector import ProactiveDecisionThreatDetector
from src.config import Settings, get_settings
from src.decision.circuit_breaker import DecisionCircuitBreaker
from src.decision.decision_engine import MultiCriteriaDecisionEngine
from src.models.dataset import (
    DatasetBatchMetadata,
    IngestDatasetBatchRequest,
)
from src.models.decision import (
    CircuitBreakerStatus,
    DecisionReport,
    EvaluateDecisionRequest,
)
from src.models.threat_alert import ThreatAlertRecord
from src.provenance.merkle_lineage import MerkleProvenanceEngine
from src.security.rbac import DecisionPermission, DecisionRole, DecisionSecurityGuard
from src.security.signature import DecisionSignatureService


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    current_settings = settings or get_settings()

    app = FastAPI(
        title="Sécurisation des Systèmes d'Aide à la Décision (DSS)",
        description="Lignage cryptographique par Arbres de Merkle, disjoncteur décisionnel (Circuit Breaker) et détection proactive d'empoisonnement par IA.",
        version="1.0.0",
    )

    # Composants de sécurité, décision et IA
    merkle_engine = MerkleProvenanceEngine()
    decision_engine = MultiCriteriaDecisionEngine()
    circuit_breaker = DecisionCircuitBreaker(
        min_confidence_threshold=current_settings.CIRCUIT_BREAKER_CONFIDENCE_THRESHOLD
    )
    signature_service = DecisionSignatureService(
        signature_key_hex=current_settings.DECISION_SIGNATURE_KEY_HEX
    )
    proactive_detector = ProactiveDecisionThreatDetector(
        max_zscore=current_settings.MAX_STATISTICAL_ZSCORE_DEVIATION,
        threat_threshold=current_settings.PROACTIVE_POISON_THRESHOLD,
    )

    # Référentiels en mémoire
    batches_db: Dict[str, DatasetBatchMetadata] = {}
    decisions_db: Dict[str, DecisionReport] = {}

    @app.get("/health", tags=["Monitoring"])
    async def health() -> dict:
        return {
            "status": "healthy",
            "service": "securisation-aide-decision",
            "ingested_batches": len(batches_db),
            "decisions_evaluated": len(decisions_db),
            "circuit_breaker_trips": circuit_breaker.trip_count,
            "proactive_threats_detected": len(proactive_detector.alert_history),
        }

    @app.post(
        "/api/v1/datasets/ingest",
        status_code=status.HTTP_201_CREATED,
        response_model=DatasetBatchMetadata,
        tags=["Ingestion & Traçabilité"],
    )
    async def ingest_dataset_batch(
        payload: IngestDatasetBatchRequest,
        x_user_role: str = Header("data_engineer", alias="X-User-Role"),
    ) -> DatasetBatchMetadata:
        """Ingère un lot de données, calcule son arbre de Merkle et scelle sa provenance."""
        try:
            role = DecisionRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur non valide.")

        if not DecisionSecurityGuard.has_permission(role, DecisionPermission.INGEST_DATASET):
            raise HTTPException(status_code=403, detail="Privilèges insuffisants pour ingérer des jeux de données.")

        if payload.batch_id in batches_db:
            raise HTTPException(status_code=400, detail="Ce lot de données existe déjà.")

        # 1. Calcul de l'arbre de Merkle pour garantir l'inaltérabilité de chaque enregistrement
        leaf_hashes = [merkle_engine.hash_record(rec.model_dump()) for rec in payload.records]
        merkle_root = merkle_engine.compute_merkle_root(leaf_hashes)

        # 2. Scellement par signature
        signature = signature_service.sign_decision(
            payload.batch_id, merkle_root, "BATCH_SEALED", 1.0
        )

        metadata = DatasetBatchMetadata(
            batch_id=payload.batch_id,
            source_system=payload.source_system,
            record_count=len(payload.records),
            merkle_root_hash=merkle_root,
            ingested_at=time.time(),
            integrity_signature=signature,
        )

        batches_db[payload.batch_id] = metadata
        return metadata

    @app.post(
        "/api/v1/decisions/evaluate",
        status_code=status.HTTP_200_OK,
        response_model=DecisionReport,
        tags=["Inférence Décisionnelle"],
    )
    async def evaluate_decision(
        payload: EvaluateDecisionRequest,
        x_user_role: str = Header("cdo", alias="X-User-Role"),
    ) -> DecisionReport:
        """
        Évalue une recommandation stratégique après détection proactive d'empoisonnement par l'IA
        et validation par le disjoncteur de sécurité (Circuit Breaker).
        """
        try:
            role = DecisionRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur non valide.")

        if not DecisionSecurityGuard.has_permission(role, DecisionPermission.TRIGGER_DECISION):
            raise HTTPException(status_code=403, detail="Privilèges insuffisants pour solliciter le système décisionnel.")

        if payload.dataset_batch_id not in batches_db:
            raise HTTPException(status_code=404, detail="Lot de données source introuvable.")

        batch_meta = batches_db[payload.dataset_batch_id]

        # 1. Détection Proactive par l'IA (Empoisonnement, Z-score anormal, Injection)
        is_threat, risk_score, threat_reasons, _, _ = proactive_detector.evaluate_proactive_threats(
            payload.input_parameters
        )

        # 2. Inférence nominale du moteur multi-critères
        nominal_action, confidence, contributions = decision_engine.evaluate(payload.input_parameters)

        # 3. Disjoncteur décisionnel (Circuit Breaker)
        effective_action, cb_status, fallback_applied, warnings = circuit_breaker.check_and_safeguard(
            nominal_action=nominal_action,
            confidence_score=confidence,
            proactive_threat_detected=is_threat,
            threat_reasons=threat_reasons,
        )

        # 4. Calcul de l'empreinte de provenance cryptographique (Lignage)
        prov_hash = merkle_engine.compute_decision_provenance(
            batch_merkle_root=batch_meta.merkle_root_hash,
            input_params=payload.input_parameters,
            decision_context_id=payload.decision_context_id,
        )

        decision_id = f"DEC-{uuid.uuid4().hex[:8].upper()}"
        decision_sig = signature_service.sign_decision(
            decision_id, prov_hash, effective_action, confidence
        )

        report = DecisionReport(
            decision_id=decision_id,
            decision_context_id=payload.decision_context_id,
            recommended_action=effective_action,
            confidence_score=confidence,
            circuit_breaker_status=cb_status,
            feature_contributions=contributions,
            provenance_hash=prov_hash,
            decision_signature=decision_sig,
            evaluated_at=time.time(),
            fallback_applied=fallback_applied,
            warning_messages=warnings,
        )

        decisions_db[decision_id] = report
        return report

    @app.get(
        "/api/v1/provenance/lineage/{decision_id}",
        tags=["Traçabilité & Provenance"],
    )
    async def get_decision_lineage(decision_id: str) -> dict:
        """Vérifie la chaîne de confiance et l'intégrité de la décision à partir de sa racine de Merkle."""
        if decision_id not in decisions_db:
            raise HTTPException(status_code=404, detail="Décision introuvable.")

        dec = decisions_db[decision_id]
        is_valid_sig = signature_service.verify_decision_signature(
            decision_id=dec.decision_id,
            provenance_hash=dec.provenance_hash,
            action=dec.recommended_action,
            confidence=dec.confidence_score,
            signature=dec.decision_signature,
        )

        return {
            "decision_id": dec.decision_id,
            "provenance_hash": dec.provenance_hash,
            "signature_valid": is_valid_sig,
            "circuit_breaker_status": dec.circuit_breaker_status.value,
            "fallback_applied": dec.fallback_applied,
            "verified_at": time.time(),
        }

    @app.get(
        "/api/v1/ai/threats/alerts",
        response_model=List[ThreatAlertRecord],
        tags=["Supervision IA & Menaces"],
    )
    async def get_threat_alerts() -> List[ThreatAlertRecord]:
        """Consulte les alertes d'empoisonnement et menaces proactives interceptées par l'IA."""
        return proactive_detector.alert_history

    return app


app = create_app()
