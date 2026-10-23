# Architecture Système - Sécurisation des Systèmes d'Aide à la Décision (DSS)

## 1. Vue d'Ensemble & Intégrité Décisionnelle

Les systèmes d'aide à la décision (Decision Support Systems - DSS) et de Business Intelligence stratégique traitent des volumes massifs de données pour orienter les investissements, les choix thérapeutiques et l'allocation de ressources critiques. La plateforme garantit l'intégrité de bout en bout contre l'empoisonnement de données et les décisions biaisées.

```mermaid
flowchart TD
    subgraph Data_Lake["Flux de Données & Entrepôt Stratégique"]
        RAW_BATCH["Lots de Données Brutes (Data Batches)"]
    end

    subgraph Provenance_Gate["Ingestion & Scellement Cryptographique"]
        MERKLE["Arbre de Merkle (Merkle Root)"]
        BATCH_SIG["Signature HMAC de Lot Scellé"]
    end

    subgraph Proactive_AI["Intelligence Artificielle Proactive"]
        Z_SCORE["Analyse Statistique d'Écart (Z-Score > 3.5)"]
        NOISE_DET["Détecteur de Perturbations Contradictoires"]
        DRIFT_DET["Surveillance de Dérive de Distribution"]
    end

    subgraph Decision_Core["Cœur Décisionnel & Garde-Fou"]
        CIRCUIT_BREAKER["Disjoncteur Décisionnel (Circuit Breaker)"]
        DECISION_ENGINE["Moteur Multi-Critères & Explicabilité"]
        SAFE_FALLBACK["Mode Repli Sécurisé (Revue Manuelle)"]
    end

    subgraph Governance["Traçabilité & Consommation"]
        CDO["Directeur Décisionnel (CDO)"]
        AUDITOR["Auditeur de Risques & Conformité"]
        LINEAGE_DAG["Graphe de Lignage Cryptographique (DAG)"]
    end

    RAW_BATCH --> MERKLE
    MERKLE --> BATCH_SIG

    CDO -->|Paramètres d'Évaluation| Proactive_AI
    Proactive_AI --> Z_SCORE & NOISE_DET & DRIFT_DET

    Proactive_AI -->|Vérification Menace| CIRCUIT_BREAKER
    CIRCUIT_BREAKER -->|Si Sûr (Nominal)| DECISION_ENGINE
    CIRCUIT_BREAKER -->|Si Menace Détectée| SAFE_FALLBACK

    DECISION_ENGINE --> LINEAGE_DAG
    SAFE_FALLBACK --> LINEAGE_DAG
    LINEAGE_DAG --> AUDITOR
```

## 2. Piliers d'Architecture & Sécurité

### 2.1 Lignage Cryptographique par Arbres de Merkle
Chaque lot de données ingéré est structuré en arbre de Merkle. La racine `merkle_root_hash` est scellée par signature HMAC-SHA256. Toute décision ultérieure dérive une empreinte de lignage associant mathématiquement la racine exacte du lot, les paramètres d'entrée et le contexte exécutif, interdisant toute modification rétroactive ou falsification de preuves.

### 2.2 Disjoncteur Décisionnel (Circuit Breaker)
Le disjoncteur protège le management contre l'illusion de certitude :
- Si l'IA proactive détecte une tentative d'empoisonnement de données, le disjoncteur se déclenche immédiatement.
- Si le score de confiance de l'algorithme tombe sous le seuil critique (65%), la recommandation automatisée est bloquée et basculée en mode repli avec obligation de validation humaine par un officier accrédité.

### 2.3 Variante IA : Détection Proactive des Menaces
Plutôt que d'attendre les impacts d'une mauvaise décision, l'IA proactive intercepte les manipulations en amont :
- **Détection d'Empoisonnement Statistique :** Contrôle de déviation multivariée par Z-score par rapport aux distributions historiques de référence (détection de valeurs aberrantes insérées pour fausser les pondérations).
- **Injection Contradictoire (Adversarial Perturbation) :** Détection de valeurs hors domaine physique (ex: ratios négatifs impossibles) cherchant à provoquer des erreurs de division ou des retournements de logique.
