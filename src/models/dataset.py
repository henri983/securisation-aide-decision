"""
Modèles liés aux jeux de données décisionnels et à leur traçabilité.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DataRecord(BaseModel):
    record_id: str
    features: Dict[str, float]
    metadata: Optional[Dict[str, str]] = None


class IngestDatasetBatchRequest(BaseModel):
    batch_id: str = Field(..., examples=["BATCH-2026-Q4-01"])
    source_system: str = Field(..., examples=["ERP_FINANCE_ANALYTICS"])
    records: List[DataRecord]


class DatasetBatchMetadata(BaseModel):
    batch_id: str
    source_system: str
    record_count: int
    merkle_root_hash: str
    ingested_at: float
    integrity_signature: str
