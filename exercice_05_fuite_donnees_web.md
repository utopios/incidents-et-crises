# Exercice 05 : Rédaction d'un rapport d'incident professionnel

## Informations pratiques

| Élément | Valeur |
|---------|--------|
| **Mode** | Individuel |
| **Livrable** | Rapport d'incident complet (format template) |

---

## Objectifs pédagogiques

À l'issue de cet exercice, vous serez capable de :
1. Rédiger un rapport d'incident professionnel structuré
2. Utiliser le template ISO 27035
3. Présenter des informations techniques de manière claire
4. Formuler des recommandations actionnables
5. Documenter pour les aspects juridiques et conformité

---

## Contexte

Vous êtes **analyste CIRT** chez **TechCare Solutions**, une plateforme SaaS de gestion des dossiers médicaux.

Vous venez de gérer un incident de sécurité et devez maintenant **rédiger le rapport d'incident** destiné à :
- La Direction (COMEX)
- Le CISO
- L'équipe développement
- L'équipe infrastructure
- L'autorité de protection des données (CNIL)
- Les clients affectés

---

## Déroulement de l'incident (chronologie)

### Jeudi 13 février 2024

**14h22** : Alerte du système de monitoring sur le serveur API production (api-prod-01)
- Alerte : Augmentation anormale du trafic HTTP (200 requêtes/seconde vs moyenne 30)
- Volume de réponses 404 très élevé (scanning de répertoires)

**14h25** : L'analyste CIRT (vous) commence l'investigation

**14h35** : Analyse des logs d'accès Apache
- Source IP : `203.0.113.42` (géolocalisation : Roumanie)
- Pattern détecté : Énumération de paramètres GET
- Tentatives d'accès à : `/api/patients?patientId=1`, `/api/patients?patientId=2`, etc.
- **Aucune authentification requise** sur cet endpoint (vulnérabilité)

**14h45** : Reconnaissance d'une vulnérabilité connue
- **CVE-2024-1234** : Insecure Direct Object Reference (IDOR) dans la version 2.1.0 du framework API utilisé
- Le endpoint `/api/patients` n'appliquait pas de vérification d'autorisation
- Chaque patient pouvait accéder aux dossiers d'autres patients en modifiant le paramètre `patientId`

**15h00** : Estimation du volume d'accès non autorisés
- Logs analysés : 45 minutes d'attaque (14h22 - 15h07)
- **3 847 requêtes** vers des ressources sensibles
- **~850 enregistrements patients** accédés (ID de 1 à 850)
- Chaque enregistrement contient : nom, prénom, email, date de naissance, historique médical partiel

**15h15** : Isolation du serveur
- Redirection du trafic production vers serveur backup (api-prod-02)
- L'attaquant perd la connexion

**15h30** : Forensics approfondie
- Logs d'accès complets exportés pour analyse
- Vérification : Aucun accès en écriture (lecture seule)
- Aucune exfiltration directe détectée (mais données accessibles en lecture)
- Pas de placement de shell web ou malware

**15h45** : Vérification du périmètre
- Recherche d'autres endpoints vulnérables similaires
- **2 autres endpoints** identifiés : `/api/doctors` et `/api/appointments`
- Tous 3 présentent la même vulnérabilité IDOR

**16h00** : Patch d'urgence
- Déploiement immédiat du patch officiel du framework (version 2.1.5)
- Mise en place de contrôles d'autorisation côté application
- Vérification que chaque utilisateur ne peut accéder qu'à ses propres ressources

**16h30** : Analyse de compromission
- Vérification des exfiltrations via proxy/DLP : Aucune donnée transmise vers l'extérieur
- Verification : IP 203.0.113.42 blacklistée au niveau firewall
- Monitoring intensif des 48h suivantes

**17h00** : Communication interne
- Notification au CISO et à la direction
- Activation du groupe de crise
- Préparation de la notification CNIL

**18h00** : Analyse impact données
- Base de données : **850 dossiers patients exposés en lecture**
- Données sensibles révélées : noms, prénoms, emails, dates de naissance, pathologies
- Catégories spéciales RGPD exposées : données de santé (Article 9)

**19h30** : Notification CNIL
- Signalement effectué via le formulaire de notification
- Délai : 72h à partir du signalement
- Dossier : INC-2024-02456

**21h00** : Communication clients
- Notification email envoyée aux 850 clients affectés
- Explications simples et mesures prises
- Propositions : surveillance crédit gratuite, assurance identité 6 mois

**J+1 (14 février, 10h00)** : Fin de l'incident
- Tous les serveurs API vérifiés et patché
- Surveillance renforcée en place
- Rapport d'incident finalisé

---

## Informations complémentaires

### Analyse technique de la vulnérabilité

**Type** : Insecure Direct Object Reference (IDOR) - OWASP Top 10 #1

**Cause** :
- Endpoint REST `/api/patients/:id` acceptant un paramètre `patientId` sans contrôle d'autorisation
- Absence de vérification : "L'utilisateur courant a-t-il le droit d'accéder à ce dossier patient ?"

**Code vulnérable (conceptuel)** :
```
GET /api/patients?patientId=123
→ SELECT * FROM patients WHERE patientId = 123
→ Aucune vérification du droit d'accès
```

**Techniques MITRE ATT&CK** :
- T1526 - Reconnaissance via reconnaissance passive
- T1592 - Gather Victim Identity Information
- T1530 - Data from Cloud Storage Object
- T1041 - Exfiltration Over C2 Channel (tentée mais bloquée)

### Impact

**Impact réel** :
- Exposition en lecture de 850 dossiers patients
- Aucune modification de données
- Aucune exfiltration confirmée
- Activité métier non affectée (serveurs backup fonctionnels)

**Impact potentiel** (sans détection rapide) :
- Accès à la totalité de la base patients (10 000+ dossiers)
- Exposition de données de santé (catégories spéciales RGPD)
- Violation grave des articles 5, 32, 33 du RGPD
- Atteinte à la vie privée des patients

**Impact réputationnel** :
- Notification obligatoire à 850 clients
- Risque de diminution de confiance
- Couverture médiatique potentielle

### Coûts

- Temps analyste CIRT : 8 heures (coût : 400 €)
- Temps développeur (patch) : 4 heures (coût : 300 €)
- Temps infrastructure (migration) : 3 heures (coût : 180 €)
- Communication/notification clients : 2 heures (coût : 120 €)
- Conformité CNIL : 4 heures (coût : 240 €)
- Assurance identité offerte (6 mois × 850 clients) : 15 000 €
- **Total** : ~16 240 €

### Causes racines identifiées

1. **Technique** :
   - Absence de security review du code avant déploiement
   - Framework API non à jour (version 2.1.0 vulnérable)
   - Pas de tests d'autorisation en CI/CD
   - Absence de Web Application Firewall (WAF)

2. **Processuelle** :
   - Cycle de patching mensuel trop lent (CVE publiée depuis 3 semaines)
   - Pas de processus d'escalade automatique des vulnérabilités critiques
   - Monitoring insuffisant sur les endpoints sensibles

3. **Organisationnelle** :
   - Équipe DevOps réduite, pas de capacity pour patching immédiat
   - Pas de formation sécurité applicative pour développeurs

---

## Votre travail : Rédiger le rapport

### Consigne

Rédigez le rapport d'incident complet en respectant le template ISO 27035.



---

## Bonus

### 1. Timeline visuelle

Créez un diagramme Gantt montrant :
- Les phases de l'incident (détection → isolation → patch → notification)
- Les parallélisations possibles
- Les délais critiques (72h CNIL, etc.)



---

### 2. Matrice de risque

Créez une matrice avant/après montrant :
- Probabilité vs Impact pour la vulnérabilité IDOR
- L'effet du patch
- Les mesures de détection/prévention


---

### 3. Matrice RGPD

Analysez l'incident selon le RGPD :
- Article 33 (notification CNIL) : Applicable ?
- Article 34 (notification personnes) : Nécessaire ?
- Droit à l'oubli : Implémentation en cas de demande
- Audit de conformité : Calendrier proposé

