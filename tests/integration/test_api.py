"""
Tests d'intégration end-to-end de l'API FastAPI d'aide à la décision sécurisée.
"""

import pytest
import httpx


@pytest.mark.asyncio
async def test_health_check(async_client: httpx.AsyncClient):
    """Vérifie l'état de fonctionnement du service."""
    res = await async_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "securisation-aide-decision"


@pytest.mark.asyncio
async def test_complete_decision_pipeline_and_proactive_protection(async_client: httpx.AsyncClient):
    """
    Scénario d'intégration décisionnel complet :
    1. Ingestion d'un lot de données avec calcul d'arbre de Merkle
    2. Évaluation décisionnelle nominale légitime
    3. Injection d'une donnée empoisonnée (Data Poisoning) interceptée par l'IA
    4. Déclenchement automatique du disjoncteur (Circuit Breaker) en mode repli
    5. Vérification du lignage cryptographique et de la non-répudiation
    6. Consultation des alertes de menaces proactives
    """
    batch_id = "BATCH-FINANCE-2026-Q4"

    # 1. Ingestion d'un lot de données
    ingest_payload = {
        "batch_id": batch_id,
        "source_system": "SAP_ENTERPRISE_DATA_LAKE",
        "records": [
            {"record_id": "REC-01", "features": {"revenue_growth": 0.08, "solvency_ratio": 1.62}},
            {"record_id": "REC-02", "features": {"revenue_growth": 0.09, "solvency_ratio": 1.58}},
        ],
    }
    ingest_res = await async_client.post(
        "/api/v1/datasets/ingest",
        json=ingest_payload,
        headers={"X-User-Role": "data_engineer"},
    )
    assert ingest_res.status_code == 201
    batch_meta = ingest_res.json()
    assert "merkle_root_hash" in batch_meta
    assert len(batch_meta["merkle_root_hash"]) == 64

    # 2. Inférence décisionnelle nominale légitime
    eval_payload = {
        "decision_context_id": "CTX-STRATEGIC-ACQUISITION-01",
        "dataset_batch_id": batch_id,
        "input_parameters": {
            "revenue_growth": 0.12,
            "solvency_ratio": 1.80,
            "operational_risk": 0.18,
        },
        "requestor_id": "CDO-EXECUTIVE",
    }
    eval_res = await async_client.post(
        "/api/v1/decisions/evaluate",
        json=eval_payload,
        headers={"X-User-Role": "cdo"},
    )
    assert eval_res.status_code == 200
    report = eval_res.json()
    assert report["circuit_breaker_status"] == "nominal"
    assert report["fallback_applied"] is False
    assert report["recommended_action"] == "APPROVE_STRATEGIC_EXPANSION"
    decision_id = report["decision_id"]

    # 3. Tentative d'empoisonnement statistique (Croissance = 95%, Z-score extrême)
    poisoned_payload = {
        "decision_context_id": "CTX-POISONED-ATTACK-01",
        "dataset_batch_id": batch_id,
        "input_parameters": {
            "revenue_growth": 0.95,
            "solvency_ratio": 1.80,
            "operational_risk": 0.18,
        },
        "requestor_id": "HOSTILE-ACTOR",
    }
    poisoned_res = await async_client.post(
        "/api/v1/decisions/evaluate",
        json=poisoned_payload,
        headers={"X-User-Role": "cdo"},
    )
    assert poisoned_res.status_code == 200
    poisoned_report = poisoned_res.json()

    # Le disjoncteur doit avoir neutralisé l'attaque en basculant en repli sécurisé
    assert poisoned_report["circuit_breaker_status"] == "triggered_safe_fallback"
    assert poisoned_report["fallback_applied"] is True
    assert poisoned_report["recommended_action"] == "SAFE_FALLBACK_MANUAL_REVIEW_REQUIRED"
    assert any("Empoisonnement" in w for w in poisoned_report["warning_messages"])

    # 4. Vérification de la preuve de lignage cryptographique (Provenance DAG)
    lineage_res = await async_client.get(f"/api/v1/provenance/lineage/{decision_id}")
    assert lineage_res.status_code == 200
    lineage_data = lineage_res.json()
    assert lineage_data["signature_valid"] is True
    assert lineage_data["decision_id"] == decision_id

    # 5. Consultation des alertes de menaces proactives
    threats_res = await async_client.get("/api/v1/ai/threats/alerts")
    assert threats_res.status_code == 200
    threats = threats_res.json()
    assert len(threats) >= 1
    assert threats[-1]["category"] == "data_poisoning"
    assert threats[-1]["circuit_breaker_tripped"] is True
