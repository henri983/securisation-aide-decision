# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et adhère au [Versionnage Sémantique (SemVer)](https://semver.org/).

## [1.0.0] - 2026-10-23

### Ajouts Initiaux (v1.0.0 Release)
- **Traçabilité & Lignage Cryptographique (Data Lineage) :**
  - Moteur d'arbres de Merkle pour le scellement de lots de données.
  - Preuve mathématique de provenance reliant chaque décision à sa source exacte.
  - Signatures HMAC-SHA256 non répudiables sur les décisions stratégiques.
- **Disjoncteur Décisionnel (Decision Circuit Breaker) :**
  - Mode nominal et repli sécurisé automatique (`SAFE_FALLBACK_MANUAL_REVIEW_REQUIRED`).
  - Déclenchement automatique lors de menaces proactives ou de confiance insuffisante (< 65%).
- **Moteur Décisionnel Multi-Critères :**
  - Évaluation pondérée et vecteur d'attribution des features (explicabilité de décision).
  - Contrôle d'accès RBAC (CDO, Data Engineer, Auditeur de Risque, Observateur).
- **Variante Intelligence Artificielle - Détection Proactive :**
  - Détection proactive d'empoisonnement de données par déviation de Z-score (> 3.5).
  - Interception des perturbations contradictoires (valeurs négatives aberrantes).
  - Enregistrement continu des alertes et des déclenchements de disjoncteurs.
- **Assurance Qualité & Tests :**
  - Suite complète de 20 tests automatisés avec 100% de réussite.
  - Pipeline GitHub Actions CI pour vérification continue, linter Ruff et scan Bandit.
