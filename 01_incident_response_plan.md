# Plan de Réponse aux Incidents (IRP)
## [NOM DE L'ENTREPRISE]

**Version**: 2.1
**Date de création**: 01/01/2024
**Dernière mise à jour**: 15/01/2024
**Propriétaire**: RSSI
**Classification**: CONFIDENTIEL - USAGE INTERNE

---

## Table des Matières

1. [Introduction](#1-introduction)
2. [Périmètre et Objectifs](#2-périmètre-et-objectifs)
3. [Rôles et Responsabilités](#3-rôles-et-responsabilités)
4. [Classification des Incidents](#4-classification-des-incidents)
5. [Procédures de Détection](#5-procédures-de-détection)
6. [Procédures de Réponse](#6-procédures-de-réponse)
7. [Communication](#7-communication)
8. [Outils et Ressources](#8-outils-et-ressources)
9. [Tests et Maintenance](#9-tests-et-maintenance)
10. [Annexes](#10-annexes)

---

## 1. Introduction

### 1.1 Contexte

Ce Plan de Réponse aux Incidents (IRP) définit les procédures et processus que [NOM ENTREPRISE] doit suivre pour détecter, analyser, contenir et éradiquer les incidents de sécurité informatique.

### 1.2 Références

| Document | Version | Description |
|----------|---------|-------------|
| NIST SP 800-61 Rev.2 | 2012 | Computer Security Incident Handling Guide |
| ISO 27001:2022 | A.16 | Gestion des incidents de sécurité |
| RGPD | Art. 33-34 | Notification de violation de données |
| Politique de Sécurité | v3.0 | Politique interne de sécurité SI |

### 1.3 Approbation

| Rôle | Nom | Signature | Date |
|------|-----|-----------|------|
| Directeur Général | [NOM] | _________ | __/__/____ |
| RSSI | [NOM] | _________ | __/__/____ |
| DSI | [NOM] | _________ | __/__/____ |
| DPO | [NOM] | _________ | __/__/____ |

---

## 2. Périmètre et Objectifs

### 2.1 Périmètre

Ce plan s'applique à :

**Systèmes couverts :**
- Infrastructure réseau (LAN, WAN, DMZ)
- Serveurs de production et développement
- Postes de travail et terminaux mobiles
- Applications métier critiques
- Services Cloud (IaaS, PaaS, SaaS)
- Systèmes industriels (OT/ICS) - si applicable

**Exclusions :**
- Systèmes des prestataires externes (sauf clause contractuelle)
- Équipements personnels non enrôlés (BYOD non managé)

### 2.2 Objectifs

| Objectif | Métrique Cible |
|----------|----------------|
| Réduire le temps de détection (MTTD) | < 24 heures |
| Réduire le temps de réponse (MTTR) | < 4 heures (P1) |
| Réduire le temps de confinement (MTTC) | < 1 heure (P1) |
| Minimiser l'impact business | Interruption < 4h |
| Assurer la conformité réglementaire | 100% |
| Préserver les preuves | 100% des P1/P2 |

---

## 3. Rôles et Responsabilités

### 3.1 Structure Organisationnelle

```
                    ┌─────────────────────────┐
                    │   Comité de Direction    │
                    │   (Incidents P1)         │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │         RSSI            │
                    │   Incident Manager      │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────▼───────┐     ┌────────▼────────┐     ┌───────▼───────┐
│   SOC/CSIRT   │     │   IT Operations │     │   Juridique   │
│   Technique   │     │   Support       │     │   DPO         │
└───────────────┘     └─────────────────┘     └───────────────┘
```

### 3.2 Matrice RACI

| Activité | RSSI | SOC L1 | SOC L2 | IT Ops | DPO | DirCom | Direction |
|----------|------|--------|--------|--------|-----|--------|-----------|
| Détection d'alerte | I | R | C | I | - | - | - |
| Triage et classification | A | R | C | I | - | - | - |
| Escalade P1/P2 | R | R | A | C | I | I | I |
| Confinement technique | A | C | R | R | I | - | I |
| Investigation forensique | A | - | R | C | C | - | I |
| Communication interne | A | - | C | C | C | R | A |
| Notification CNIL | C | - | - | - | R | C | A |
| Communication externe | C | - | - | - | C | R | A |
| Décision de payer rançon | C | - | - | - | C | C | R/A |
| Restauration systèmes | A | I | C | R | - | - | I |
| Post-mortem | R | C | C | C | C | - | I |

**Légende**: R = Responsable, A = Accountable, C = Consulté, I = Informé

### 3.3 Fiches de Poste Incident Response

#### 3.3.1 Incident Manager (RSSI ou délégué)

**Responsabilités :**
- Coordonner l'ensemble de la réponse à l'incident
- Prendre les décisions critiques (confinement, communication)
- Assurer le reporting vers la direction
- Valider la clôture de l'incident

**Compétences requises :**
- Certification GCIH ou équivalent
- Expérience en gestion de crise
- Connaissance du SI de l'entreprise

**Contact :**
- Principal : [NOM] - [TEL] - [EMAIL]
- Backup : [NOM] - [TEL] - [EMAIL]

#### 3.3.2 Analyste SOC Niveau 2

**Responsabilités :**
- Analyser les alertes escaladées par le niveau 1
- Conduire l'investigation technique
- Proposer et implémenter les mesures de confinement
- Documenter les actions et preuves

**Compétences requises :**
- Analyse forensique (mémoire, disque, réseau)
- Connaissance SIEM/EDR
- Scripting (Python, PowerShell)

---

## 4. Classification des Incidents

### 4.1 Niveaux de Sévérité

#### P1 - Critique (Rouge)

**Critères (au moins un) :**
- Impact sur la continuité d'activité (arrêt production)
- Compromission de données personnelles sensibles (>1000 personnes)
- Ransomware actif avec chiffrement en cours
- Compromission de compte à privilèges élevés (admin domaine)
- Attaque ciblée confirmée (APT)
- Risque médiatique imminent

**SLA :**
- Réponse initiale : < 15 minutes
- Escalade direction : < 30 minutes
- Confinement : < 1 heure
- Update toutes les : 30 minutes

#### P2 - Élevé (Orange)

**Critères (au moins un) :**
- Compromission d'un système critique sans propagation
- Malware détecté sur plusieurs postes
- Exfiltration de données suspectée
- Compte utilisateur compromis avec accès sensibles
- Phishing réussi avec credentials volés

**SLA :**
- Réponse initiale : < 1 heure
- Escalade RSSI : < 2 heures
- Confinement : < 4 heures
- Update toutes les : 2 heures

#### P3 - Moyen (Jaune)

**Critères :**
- Malware isolé sur un poste
- Tentative d'intrusion bloquée
- Phishing détecté et signalé (pas de clic)
- Anomalie de configuration détectée

**SLA :**
- Réponse initiale : < 4 heures
- Résolution : < 24 heures
- Update : quotidien

#### P4 - Bas (Vert)

**Critères :**
- Scan de reconnaissance détecté
- Tentatives de connexion échouées (non massives)
- Violation mineure de politique
- Faux positif confirmé (pour documentation)

**SLA :**
- Réponse initiale : < 24 heures
- Résolution : < 72 heures

### 4.2 Matrice Impact x Urgence

|            | Urgence Faible | Urgence Moyenne | Urgence Haute |
|------------|----------------|-----------------|---------------|
| **Impact Fort** | P2 | P1 | P1 |
| **Impact Moyen** | P3 | P2 | P2 |
| **Impact Faible** | P4 | P3 | P3 |

### 4.3 Critères d'Impact

| Critère | Faible (1) | Moyen (2) | Fort (3) |
|---------|------------|-----------|----------|
| Utilisateurs affectés | < 10 | 10-100 | > 100 |
| Systèmes impactés | 1 non-critique | Multiple ou 1 critique | Plusieurs critiques |
| Données concernées | Publiques | Internes | Confidentielles/Personnelles |
| Durée d'interruption | < 1h | 1-4h | > 4h |
| Impact financier | < 10K€ | 10K-100K€ | > 100K€ |
| Impact réglementaire | Aucun | Possible | Certain (RGPD, etc.) |
| Impact réputationnel | Aucun | Limité | Significatif |

---

## 5. Procédures de Détection

### 5.1 Sources de Détection

| Source | Outil | Responsable | SLA Review |
|--------|-------|-------------|------------|
| SIEM | Splunk Enterprise | SOC L1 | Temps réel |
| EDR | CrowdStrike Falcon | SOC L1 | Temps réel |
| IDS/IPS | Suricata | SOC L1 | Temps réel |
| Email Gateway | Proofpoint | SOC L1 | Temps réel |
| Firewall | Palo Alto | NOC | 4h |
| Utilisateurs | ServiceNow | Helpdesk | 4h |
| Threat Intel | MISP | SOC L2 | Quotidien |
| Vulnerability Scanner | Qualys | Vuln. Manager | Hebdomadaire |

### 5.2 Critères de Détection Automatique

#### Règles de corrélation SIEM prioritaires

| ID Règle | Description | Sévérité Auto |
|----------|-------------|---------------|
| CORR-001 | 5+ échecs auth puis succès même source | P2 |
| CORR-002 | Connexion admin hors heures + nouveau device | P2 |
| CORR-003 | Exécution PowerShell encodé + connexion externe | P1 |
| CORR-004 | Volume transfert sortant > seuil + destination nouvelle | P2 |
| CORR-005 | Création tâche planifiée + exécution binaire non signé | P2 |
| CORR-006 | Modification fichiers masse (>100/min) | P1 |
| CORR-007 | Connexion C2 connu (IOC match) | P1 |

### 5.3 Processus de Signalement Utilisateur

```
Utilisateur détecte anomalie
        │
        ▼
┌─────────────────────────────┐
│ Email: security@company.com │
│ Tel: +33 1 XX XX XX XX      │
│ Portail: https://security   │
└───────────────┬─────────────┘
                │
                ▼
    Helpdesk crée ticket
    (Catégorie: Sécurité)
                │
                ▼
    Escalade automatique
    vers queue SOC
                │
                ▼
    SOC L1 prend en charge
    (< 15 min heures ouvrées)
```

---

## 6. Procédures de Réponse

### 6.1 Workflow Global

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  DÉTECTION   │───▶│   TRIAGE     │───▶│  ANALYSE     │───▶│ CONFINEMENT  │
│              │    │              │    │              │    │              │
│ • Alerte     │    │ • Validation │    │ • Scope      │    │ • Isolation  │
│ • Signalement│    │ • Classif.   │    │ • IOC        │    │ • Blocage    │
│              │    │ • Escalade   │    │ • Timeline   │    │ • Preserve   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                                                    │
┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
│ POST-MORTEM  │◀───│  RECOVERY    │◀───│ ÉRADICATION  │◀───────────┘
│              │    │              │    │              │
│ • Rapport    │    │ • Restore    │    │ • Nettoyage  │
│ • Lessons    │    │ • Validation │    │ • Patch      │
│ • Actions    │    │ • Monitoring │    │ • Hardening  │
└──────────────┘    └──────────────┘    └──────────────┘
```

### 6.2 Procédure Détaillée - Incident P1

#### Phase 1 : Détection et Triage (0-15 min)

**Actions SOC L1 :**

1. **Réception de l'alerte**
   - Noter l'heure exacte de détection
   - Identifier la source (SIEM, EDR, utilisateur, etc.)
   - Créer le ticket incident dans TheHive

2. **Validation initiale**
   ```
   [ ] L'alerte est-elle un faux positif évident ?
   [ ] Y a-t-il des alertes corrélées ?
   [ ] Le système source est-il connu/légitime ?
   [ ] L'activité correspond-elle à une maintenance planifiée ?
   ```

3. **Classification**
   - Appliquer la matrice de classification
   - Si P1/P2 → Escalade immédiate

4. **Escalade P1**
   - Appeler l'Incident Manager (ne pas attendre l'email)
   - Envoyer le brief initial via canal sécurisé

**Template Brief Initial :**
```
ALERTE P1 - [TITRE COURT]
========================
Heure détection: HH:MM
Source: [SIEM/EDR/User/...]
Système(s): [Liste]
Description: [2-3 lignes]
IOC identifiés: [IP/Hash/Domaine]
Action immédiate recommandée: [Isolation/Blocage/...]
Analyste: [Nom]
```

#### Phase 2 : Analyse (15 min - 1h)

**Actions SOC L2 :**

1. **Établir le scope**
   - Identifier tous les systèmes potentiellement impactés
   - Requêter le SIEM sur les IOC identifiés
   - Vérifier les connexions latérales

2. **Collecter les preuves**
   - Capturer la mémoire si système actif (priorité haute)
   - Exporter les logs pertinents
   - Screenshot si nécessaire
   - Préserver la chaîne de custody

3. **Construire la timeline**
   - Heure de compromission initiale estimée
   - Progression de l'attaque
   - Actions de l'attaquant identifiées

4. **Identifier les TTPs**
   - Mapper sur MITRE ATT&CK
   - Rechercher dans la threat intel

#### Phase 3 : Confinement (< 1h pour P1)

**Décisions de confinement (Incident Manager) :**

| Option | Description | Quand l'utiliser |
|--------|-------------|------------------|
| Isolation réseau | Couper les connexions réseau | Propagation active |
| Isolation endpoint | Quarantaine EDR | Malware détecté |
| Blocage périmétrique | Bloquer IP/domaine sur FW | C2 identifié |
| Désactivation compte | Verrouiller credentials | Compte compromis |
| Arrêt service | Stopper application | Vulnérabilité exploitée |

**Checklist Confinement :**
```
[ ] Impact du confinement évalué avec les métiers
[ ] Communication préalable si arrêt service
[ ] Preuves préservées AVANT action
[ ] Action documentée (qui, quoi, quand)
[ ] Vérification de l'efficacité du confinement
```

#### Phase 4 : Éradication

**Actions :**

1. **Supprimer la menace**
   - Nettoyer le malware (AV/EDR)
   - Supprimer les comptes créés par l'attaquant
   - Retirer les backdoors
   - Supprimer les tâches planifiées malveillantes

2. **Corriger la vulnérabilité**
   - Appliquer le patch si disponible
   - Mettre en place un workaround si pas de patch
   - Renforcer la configuration

3. **Rotation des secrets**
   - Changer les mots de passe compromis
   - Révoquer les tokens/sessions
   - Régénérer les clés API si nécessaire

**Checklist Éradication :**
```
[ ] Tous les systèmes compromis identifiés
[ ] Malware supprimé de tous les systèmes
[ ] Persistence supprimée (cron, services, registre)
[ ] Comptes malveillants supprimés
[ ] Vulnérabilité corrigée ou mitigée
[ ] Credentials compromis changés
[ ] Scan de vérification effectué
```

#### Phase 5 : Recovery

**Processus de restauration :**

1. **Préparation**
   - Identifier les sauvegardes saines (pré-compromission)
   - Préparer l'environnement de restauration
   - Définir l'ordre de restauration (systèmes critiques first)

2. **Restauration**
   - Restaurer depuis les backups validés
   - OU reconstruire à partir d'images gold
   - Appliquer les patchs avant mise en ligne

3. **Validation**
   - Scan de sécurité complet
   - Tests fonctionnels
   - Vérification des logs
   - Validation par le métier

4. **Remise en production**
   - Surveillance renforcée (24-48h)
   - Alertes spécifiques activées
   - Point de contact identifié

#### Phase 6 : Post-Incident

Voir section dédiée et template de rapport.

---

## 7. Communication

### 7.1 Matrice de Communication

| Destinataire | P1 | P2 | P3 | P4 | Canal | Responsable |
|--------------|----|----|----|----|-------|-------------|
| SOC Team | Immédiat | Immédiat | < 4h | < 24h | Teams/Slack | SOC L1 |
| RSSI | < 15 min | < 1h | Daily | Weekly | Appel + Email | SOC L2 |
| DSI | < 30 min | < 2h | Si besoin | - | Appel | RSSI |
| Direction | < 1h | < 4h | - | - | Réunion | RSSI |
| DPO | < 1h | < 4h | Si données | - | Email | RSSI |
| Juridique | < 2h | < 4h | Si besoin | - | Email | RSSI |
| Communication | < 2h | Si médias | - | - | Réunion | Direction |
| Métiers impactés | < 1h | < 2h | < 8h | - | Email/Teams | Incident Mgr |
| CNIL | < 72h | < 72h | - | - | Portail CNIL | DPO |
| Clients | Variable | Variable | - | - | Email/Portail | DirCom |

### 7.2 Templates de Communication

#### 7.2.1 Communication Interne - Initial

**Objet**: [URGENT] Incident de sécurité en cours - [ID]

```
À l'attention de [DESTINATAIRES],

Notre équipe de sécurité a détecté un incident de sécurité à [HEURE].
La situation est actuellement sous contrôle et nos équipes travaillent
à sa résolution.

SITUATION ACTUELLE:
- Type d'incident: [Description générale]
- Systèmes concernés: [Liste]
- Impact utilisateurs: [Description]

ACTIONS EN COURS:
- [Action 1]
- [Action 2]

CE QUE VOUS DEVEZ FAIRE:
- [Instruction 1]
- [Instruction 2]
- Signaler toute anomalie à security@company.com

PROCHAIN POINT D'INFORMATION: [Date/Heure]

Pour toute question urgente: [Contact]

L'équipe Sécurité
```

#### 7.2.2 Notification CNIL (si données personnelles)

Voir formulaire CNIL : https://notifications.cnil.fr/notifications/

**Informations requises :**
- Nature de la violation
- Catégories et nombre de personnes concernées
- Catégories et nombre d'enregistrements
- Coordonnées DPO
- Conséquences probables
- Mesures prises

### 7.3 Canaux de Communication Sécurisés

| Situation | Canal Principal | Canal Backup |
|-----------|-----------------|--------------|
| Communication SOC | Slack #incident-[ID] | Signal groupe |
| Cellule de crise | Teams "War Room" | Conf call dédié |
| Avec direction | En personne | Teams sécurisé |
| Avec autorités | Email chiffré | Téléphone |
| Documentation | TheHive/Confluence | Wiki hors-ligne |

**Important**: Ne jamais utiliser les canaux compromis pour communiquer sur l'incident !

---

## 8. Outils et Ressources

### 8.1 Inventaire des Outils

| Catégorie | Outil | Usage | Accès |
|-----------|-------|-------|-------|
| SIEM | Splunk Enterprise | Détection, investigation | siem.company.local |
| EDR | CrowdStrike Falcon | Endpoint protection | falcon.crowdstrike.com |
| SOAR | Splunk SOAR | Automatisation | soar.company.local |
| Ticketing | TheHive | Case management | thehive.company.local |
| Threat Intel | MISP | IOC management | misp.company.local |
| Forensique | KAPE, Volatility | Acquisition & analyse | Poste forensique |
| Réseau | Wireshark, Zeek | Capture & analyse | Poste SOC |
| Communication | Teams, Signal | Coordination | - |

### 8.2 Jump Bag (Kit de Réponse)

**Matériel physique :**
- [ ] Laptop forensique (write blocker intégré)
- [ ] Disques durs externes (2x 2TB minimum)
- [ ] Câbles réseau (croisé et droit)
- [ ] Adaptateurs USB (tous types)
- [ ] Clés USB bootables (Linux forensique, Windows PE)
- [ ] Documentation papier (ce plan, contacts)

**Logiciels sur clé USB :**
- KAPE (collecte Windows)
- AVML (acquisition mémoire Linux)
- FTK Imager (acquisition disque)
- Autoruns, Process Explorer (Sysinternals)
- Volatility 3
- CyLR

### 8.3 Contacts d'Urgence

| Rôle | Nom | Téléphone | Email |
|------|-----|-----------|-------|
| RSSI | [NOM] | +33 X XX XX XX XX | rssi@company.com |
| RSSI Backup | [NOM] | +33 X XX XX XX XX | rssi-backup@company.com |
| SOC Manager | [NOM] | +33 X XX XX XX XX | soc-manager@company.com |
| DPO | [NOM] | +33 X XX XX XX XX | dpo@company.com |
| DSI | [NOM] | +33 X XX XX XX XX | dsi@company.com |
| DG | [NOM] | +33 X XX XX XX XX | dg@company.com |
| Prestataire IR | [SOCIÉTÉ] | +33 X XX XX XX XX | ir@prestataire.com |
| ANSSI | - | +33 1 71 75 84 68 | cert-fr@ssi.gouv.fr |
| Assurance Cyber | [SOCIÉTÉ] | +33 X XX XX XX XX | - |

---

## 9. Tests et Maintenance

### 9.1 Programme de Tests

| Type de Test | Fréquence | Participants | Responsable |
|--------------|-----------|--------------|-------------|
| Test de notification | Mensuel | SOC, RSSI | SOC Manager |
| Exercice tabletop | Trimestriel | Cellule crise | RSSI |
| Simulation technique | Semestriel | SOC, IT | SOC Manager |
| Exercice full-scale | Annuel | Toute l'organisation | RSSI + Direction |

### 9.2 Revue du Plan

**Revue annuelle obligatoire incluant :**
- Mise à jour des contacts
- Revue des procédures
- Intégration des lessons learned
- Alignement avec les évolutions réglementaires
- Test des outils et accès

**Revue ad-hoc après :**
- Chaque incident P1/P2
- Changement organisationnel majeur
- Nouvelle réglementation
- Changement d'infrastructure significatif

### 9.3 Métriques de Performance

| KPI | Cible | Mesure | Responsable |
|-----|-------|--------|-------------|
| MTTD | < 24h | Temps compromise → détection | SOC Manager |
| MTTR | < 4h (P1) | Temps détection → réponse | SOC Manager |
| MTTC | < 1h (P1) | Temps détection → confinement | RSSI |
| Taux faux positifs | < 30% | Alertes FP / Total alertes | SOC Manager |
| Couverture assets | > 95% | Assets monitorés / Total | RSSI |
| Temps de notification | < 72h | Temps pour notifier CNIL | DPO |

---

## 10. Annexes

### Annexe A : Playbooks par Type d'Incident

1. [Ransomware Response Playbook](./playbook_ransomware.md)
2. [Phishing Response Playbook](./playbook_phishing.md)
3. [Data Breach Response Playbook](./playbook_data_breach.md)
4. [DDoS Response Playbook](./playbook_ddos.md)
5. [Insider Threat Playbook](./playbook_insider.md)
6. [Account Compromise Playbook](./playbook_account_compromise.md)

### Annexe B : Templates

1. [Template Ticket Incident](./template_ticket.md)
2. [Template Rapport d'Incident](./template_rapport.md)
3. [Template Post-Mortem](./template_postmortem.md)
4. [Template Communication Crise](./template_communication.md)

### Annexe C : Références Réglementaires

- RGPD : Articles 33 et 34
- NIS 2 : Obligations de notification
- LPM : Pour les OIV
- PCI-DSS : Section 12.10

### Annexe D : Historique des Versions

| Version | Date | Auteur | Modifications |
|---------|------|--------|---------------|
| 1.0 | 01/01/2023 | [NOM] | Version initiale |
| 2.0 | 01/06/2023 | [NOM] | Ajout playbooks, mise à jour contacts |
| 2.1 | 15/01/2024 | [NOM] | Intégration lessons learned INC-2023-042 |

---

**Document approuvé le**: __/__/____

**Prochaine revue**: __/__/____
