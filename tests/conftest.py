"""
Fixtures pytest pour l'aide à la décision sécurisée.
"""

import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI

from src.config import Settings
from src.main import create_app
from src.provenance.merkle_lineage import MerkleProvenanceEngine
from src.decision.decision_engine import MultiCriteriaDecisionEngine
from src.decision.circuit_breaker import DecisionCircuitBreaker
from src.security.signature import DecisionSignatureService
from src.ai.proactive_threat_detector import ProactiveDecisionThreatDetector


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        LOG_LEVEL="DEBUG",
        DECISION_MASTER_KEY_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        DECISION_SIGNATURE_KEY_HEX="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        CIRCUIT_BREAKER_CONFIDENCE_THRESHOLD=0.65,
        PROACTIVE_POISON_THRESHOLD=0.75,
        MAX_STATISTICAL_ZSCORE_DEVIATION=3.5,
    )


@pytest.fixture
def merkle_engine() -> MerkleProvenanceEngine:
    return MerkleProvenanceEngine()


@pytest.fixture
def decision_engine() -> MultiCriteriaDecisionEngine:
    return MultiCriteriaDecisionEngine()


@pytest.fixture
def circuit_breaker(test_settings: Settings) -> DecisionCircuitBreaker:
    return DecisionCircuitBreaker(min_confidence_threshold=test_settings.CIRCUIT_BREAKER_CONFIDENCE_THRESHOLD)


@pytest.fixture
def signature_service(test_settings: Settings) -> DecisionSignatureService:
    return DecisionSignatureService(signature_key_hex=test_settings.DECISION_SIGNATURE_KEY_HEX)


@pytest.fixture
def proactive_detector(test_settings: Settings) -> ProactiveDecisionThreatDetector:
    return ProactiveDecisionThreatDetector(
        max_zscore=test_settings.MAX_STATISTICAL_ZSCORE_DEVIATION,
        threat_threshold=test_settings.PROACTIVE_POISON_THRESHOLD,
    )


@pytest.fixture
def test_app(test_settings: Settings) -> FastAPI:
    return create_app(settings=test_settings)


@pytest_asyncio.fixture
async def async_client(test_app: FastAPI):
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
