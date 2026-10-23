# Lignage Cryptographique des Données & Arbres de Merkle

## 1. Principes du Lignage (Data Provenance)

Dans les environnements réglementés (finance, santé, industrie de défense), une recommandation automatisée ne peut être acceptée sans justification vérifiable de l'origine exacte des données utilisées.

La plateforme implémente un registre d'intégrité basé sur la cryptographie de Merkle.

## 2. Construction de l'Arbre de Merkle par Lot

Pour chaque lot de données ingéré :
1. Chaque enregistrement `record_i` est sérialisé de manière déterministe et haché en SHA-256 :
   $$L_i = \text{SHA256}(\text{JSON}(record_i))$$
2. Les feuilles sont appariées et combinées par niveaux successifs jusqu'au nœud racine :
   $$\text{Merkle Root} = \text{ComputeRoot}(L_1, L_2, \dots, L_n)$$
3. La racine de Merkle est scellée avec signature HMAC et horodatée.

## 3. Preuve de Lignage Décisionnel

Lorsqu'une décision est générée via `/api/v1/decisions/evaluate` :
$$H_{\text{provenance}} = \text{SHA256}(\text{MerkleRoot} \parallel \text{JSON}(\text{InputParams}) \parallel \text{ContextId})$$

L'endpoint `/api/v1/provenance/lineage/{decision_id}` permet à tout auditeur de revalider la conformité mathématique intégrale de la décision.
