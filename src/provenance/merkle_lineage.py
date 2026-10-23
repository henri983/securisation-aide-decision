"""
Arbre de Merkle et registre de provenance cryptographique (Cryptographic Data Lineage).
Permet de prouver mathématiquement qu'aucune donnée d'un lot n'a été altérée
entre la collecte et l'inférence décisionnelle.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional


class MerkleProvenanceEngine:
    """Moteur de construction d'arbres de Merkle et scellement de lignage."""

    @staticmethod
    def hash_record(record_dict: Dict[str, Any]) -> str:
        """Calcule la feuille de Merkle pour un enregistrement individuel."""
        serialized = json.dumps(record_dict, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @classmethod
    def compute_merkle_root(cls, leaf_hashes: List[str]) -> str:
        """Calcule la racine de Merkle (Merkle Root) à partir d'une liste de hashs de feuilles."""
        if not leaf_hashes:
            return hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()

        current_level = list(leaf_hashes)

        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # Si nombre impair de nœuds, duplique le dernier
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                next_level.append(combined)
            current_level = next_level

        return current_level[0]

    @staticmethod
    def compute_decision_provenance(
        batch_merkle_root: str,
        input_params: Dict[str, float],
        decision_context_id: str,
    ) -> str:
        """Génère l'empreinte de lignage associant le jeu de données exact à l'entrée de décision."""
        params_serialized = json.dumps(input_params, sort_keys=True)
        payload = f"{batch_merkle_root}:{params_serialized}:{decision_context_id}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
