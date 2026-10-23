"""
Tests unitaires de l'arbre de Merkle et du lignage de provenance cryptographique.
"""

import pytest
from src.provenance.merkle_lineage import MerkleProvenanceEngine


@pytest.mark.unit
def test_merkle_root_computation_deterministic(merkle_engine: MerkleProvenanceEngine):
    """Vérifie que la racine de Merkle est déterministe pour une même série d'enregistrements."""
    records = [
        {"id": "R1", "val": 10.5},
        {"id": "R2", "val": 20.3},
        {"id": "R3", "val": 35.8},
    ]

    leaves = [merkle_engine.hash_record(r) for r in records]
    root1 = merkle_engine.compute_merkle_root(leaves)
    root2 = merkle_engine.compute_merkle_root(leaves)

    assert root1 == root2
    assert len(root1) == 64


@pytest.mark.unit
def test_merkle_root_detects_single_record_tamper(merkle_engine: MerkleProvenanceEngine):
    """Toute modification, même infime, d'un seul enregistrement altère complètement la racine de Merkle."""
    records_clean = [{"id": "R1", "val": 10.0}, {"id": "R2", "val": 20.0}]
    records_tampered = [{"id": "R1", "val": 10.0001}, {"id": "R2", "val": 20.0}]

    root_clean = merkle_engine.compute_merkle_root([merkle_engine.hash_record(r) for r in records_clean])
    root_tampered = merkle_engine.compute_merkle_root([merkle_engine.hash_record(r) for r in records_tampered])

    assert root_clean != root_tampered


@pytest.mark.unit
def test_empty_merkle_tree(merkle_engine: MerkleProvenanceEngine):
    """Un arbre vide génère une racine bien définie sans exception."""
    root = merkle_engine.compute_merkle_root([])
    assert len(root) == 64


@pytest.mark.unit
def test_decision_provenance_linkage(merkle_engine: MerkleProvenanceEngine):
    """Vérifie le calcul de l'empreinte de lignage décisionnel."""
    root = "a" * 64
    params = {"growth": 0.12, "risk": 0.05}
    ctx = "CTX-STRAT-01"

    prov1 = merkle_engine.compute_decision_provenance(root, params, ctx)
    prov2 = merkle_engine.compute_decision_provenance(root, params, ctx)
    assert prov1 == prov2
    assert len(prov1) == 64
