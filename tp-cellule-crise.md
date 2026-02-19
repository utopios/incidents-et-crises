# TP : Simulation de cellule de crise

## Informations pratiques

| Élément | Valeur |
|---------|--------|
| **Durée** | 3 heures |
| **Mode** | Groupes de 6-8 personnes |
| **Type** | Jeu de rôle avec animation |
| **Livrables** | Main courante + Rapport de crise |
| **Évaluation** | Performance collective + Livrables |

---

## Objectifs pédagogiques

À l'issue de ce TP, vous serez capables de :
1. Organiser et animer une cellule de crise opérationnelle
2. Prendre des décisions sous pression temporelle
3. Gérer les communications de crise
4. Tenir une main courante
5. Coordonner plusieurs enjeux simultanés

---

## Organisation

### Répartition des rôles par groupe

Chaque groupe de 6-8 personnes doit se répartir les rôles suivants :

| Rôle | Nombre | Responsabilités |
|------|--------|-----------------|
| **Directeur de crise** | 1 | Anime la cellule, prend les décisions finales, arbitre |
| **Coordinateur de crise** | 1 | Assiste le directeur, synthétise les informations, prépare les points |
| **Responsable Communication** | 1 | Rédige les messages, gère les médias, porte-parole |
| **Responsable Opérations** | 1 | Gère les aspects opérationnels terrain |
| **Responsable IT/Sécurité** | 1 | Gère les aspects techniques et sécurité |
| **Secrétaire de crise** | 1 | Tient la main courante, note les décisions, chronomètre |
| **Observateur** | 1-2 (opt) | Observe sans intervenir, prépare le RETEX |

### Matériel nécessaire

- [ ] 1 salle par groupe (ou espaces séparés)
- [ ] Paperboard ou tableau blanc
- [ ] Ordinateur avec traitement de texte (main courante)
- [ ] Téléphones simulés ou réels pour jeux de rôle
- [ ] Horloge visible ou chronomètre

---

## Contexte : CyberHealth

### Présentation

**CyberHealth** est un éditeur de logiciels pour le secteur médical (cabinets, cliniques) créé il y a 8 ans.

### Chiffres clés

| Élément | Valeur |
|---------|--------|
| CA annuel | 25 M€ |
| Collaborateurs | 180 |
| Clients | 3 500 cabinets/cliniques |
| SaaS | 95% du CA |
| Hébergement | Cloud AWS (eu-west-3, Paris) |

### Produits

| Produit | Description | Clients |
|---------|-------------|---------|
| **MediCare** | Logiciel de gestion de cabinet médical | 2 800 |
| **CliniPro** | Logiciel pour cliniques (multi-praticiens) | 500 |
| **MediSecure** | Dossier médical électronique certifié HDS | 200 |

### Organisation

```
                    ┌─────────────────┐
                    │  CEO            │
                    │  Thomas BERNARD │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐
│ CTO           │   │ COO           │   │ CMO           │
│ Sophie MARTIN │   │ Marc DUBOIS   │   │ Julie ROUX    │
│ (DSI + R&D)   │   │ (Support)     │   │ (Com + Ventes)│
└───────┬───────┘   └───────┬───────┘   └───────────────┘
        │                   │
   ┌────┴────┐         ┌────┴────┐
   │         │         │         │
┌──▼──┐  ┌──▼──┐   ┌──▼──┐  ┌──▼──┐
│Infra│  │Dev │   │Supp │  │Qual│
│8p   │  │35p │   │50p  │  │10p │
└─────┘  └─────┘   └─────┘  └─────┘
```

### Contexte réglementaire

- **HDS** (Hébergeur de Données de Santé) : Certifié depuis 2022
- **RGPD** : Données de santé = sensibles
- **Engagement SLA** : 99,5% de disponibilité (max 3h40 d'indisponibilité/mois)

---

## Scénario : Cyberattaque par ransomware

### Phase 1 : Détection (Lundi 06h00)

```
═══════════════════════════════════════════════════════════════
                      SITUATION INITIALE
═══════════════════════════════════════════════════════════════

Date : Lundi 13 mai
Heure : 06h00 (aube)
Contexte : Week-end prolongé du 8 mai, équipes en congés

L'administrateur système d'astreinte (Kevin) reçoit des alertes
massives de son système de monitoring.

En se connectant, il constate :
- Les serveurs de production sont inaccessibles
- Les interfaces web MediCare et CliniPro retournent une erreur
- Un fichier "README_LOCKBIT.txt" est présent sur plusieurs serveurs
- Contenu : "Your data has been encrypted. Contact [email] for recovery."
```

**INJECT 1 - 06h10**

Kevin appelle Sophie MARTIN (CTO) :

> "Sophie, c'est Kevin. On a un gros problème. Les serveurs de prod sont down,
> et je pense qu'on s'est fait attaquer. Il y a des fichiers de ransomware partout.
> Les clients ne peuvent plus se connecter. Qu'est-ce que je fais ?"

---

### **PAUSE - Temps de jeu cellule : 20 minutes**

**Consignes pour les groupes :**

1. Le **Directeur de crise** active la cellule immédiatement
2. Répartissez-vous les rôles si ce n'est pas déjà fait
3. Prenez vos **premières décisions** :
   - Quel niveau de crise ?
   - Qui convoquer ?
   - Quelles actions immédiates ?
4. Le **Secrétaire** démarre la main courante

**Livrables à produire :**
- Main courante démarrée (timestamp de chaque action/décision)
- Liste des personnes convoquées
- 3-5 actions immédiates identifiées

---

### Phase 2 : Évaluation de l'impact (06h30)

**INJECT 2 - 06h30**

Bilan technique remontée par Kevin et l'équipe infrastructure :

```
SYSTÈMES TOUCHÉS :
✗ Serveurs application MediCare (8 VMs) - CHIFFRÉS
✗ Serveurs application CliniPro (4 VMs) - CHIFFRÉS
✗ Base de données principale PostgreSQL (2 serveurs) - CHIFFRÉS
✗ Serveur de fichiers (documents patients) - CHIFFRÉ
✓ Serveur de sauvegarde AWS S3 - SAIN (mais sauvegardes quotidiennes)
✓ Snapshots AWS (J-1, J-7, J-30) - SAINS
✓ Infrastructure réseau et firewall - OK

ESTIMATION RESTAURATION :
- Depuis snapshots AWS J-1 : 8-12 heures
- Perte de données : 24-48h de modifications clients
```

**INJECT 3 - 06h45**

Le support client commence à recevoir des appels :

> "Bonjour, je suis médecin et je ne peux pas accéder à mon logiciel.
> J'ai mes consultations qui commencent à 8h. C'est quoi le problème ?"

Le standard en a déjà reçu 15 en 15 minutes.

---

### **PAUSE - Temps de jeu cellule : 25 minutes**

**Consignes :**

1. **Évaluer l'impact** 

2. **Décider de la stratégie de reprise**

3. **Préparer la communication** 

4. **Actions opérationnelles**

**Livrables :**
- Décision documentée sur stratégie de reprise
- 3 messages rédigés (clients, collaborateurs, presse)
- Plan d'action opérationnel sur 12h

---

### Phase 3 : Gestion de la pression (08h00)

**INJECT 4 - 08h00**

Le Directeur Commercial appelle en urgence :

> "Thomas, j'ai un de nos plus gros clients (réseau de 50 cliniques) au téléphone.
> Ils menacent de résilier le contrat et d'aller chez notre concurrent MediSoft.
> Ils ont des blocs opératoires programmés et ne peuvent pas accéder aux dossiers
> patients. Qu'est-ce que je lui dis ?"

**INJECT 5 - 08h15**

Email reçu de l'Ordre des Médecins régional :

> Objet : Indisponibilité MediCare - Perte de chance patients
>
> Nous avons été alertés par plusieurs praticiens de l'indisponibilité de votre
> logiciel ce matin. Des consultations sont reportées, des ordonnances non éditées.
>
> Merci de nous informer rapidement de la situation et des mesures prises.
>
> Nous nous réservons le droit de saisir la CNIL si des données patients ont été
> compromises.

**INJECT 6 - 08h30**

Un journaliste de 01net appelle :

> "Bonjour, nous avons des informations selon lesquelles CyberHealth aurait été
> victime d'une cyberattaque ce week-end. Des données de santé auraient-elles
> été compromises ? Pouvez-vous confirmer ?"

---

### **PAUSE - Temps de jeu cellule : 30 minutes**

**Consignes :**

1. **Prioriser les urgences**

2. **Gérer les communications délicates**

3. **Décider des obligations légales**

**Livrables :**
- 3 réponses rédigées (client, Ordre, presse)
- Analyse des obligations RGPD
- Décision sur notification CNIL

---

### Phase 4 : La demande de rançon (10h00)

**INJECT 7 - 10h00**

L'équipe IT a pu accéder au message complet des attaquants :

```
═══════════════════════════════════════════════════════════════
                    LOCKBIT 3.0 RANSOMWARE
═══════════════════════════════════════════════════════════════

Your systems have been encrypted using military-grade encryption.

We have also EXFILTRATED 500 GB of sensitive data including:
- Patient medical records (2.5M records)
- Contracts and financial data
- Source code of your applications
- Internal communications

DEMANDS:
- Pay 100 BTC (≈ 3 M€) within 72 hours
- Contact: [adresse onion sur Tor]

IF YOU DON'T PAY:
- We will publish all data on our leak site
- We will contact your clients directly
- We will notify CNIL and press

Tick tock... 70 hours remaining.
═══════════════════════════════════════════════════════════════
```

**INJECT 8 - 10h15**

La DAF (Directrice Administrative et Financière) rappelle :

> "On a une cyberassurance avec une franchise de 500K€ et un plafond de 5M€.
> Mais le contrat exclut le paiement de rançons. Par contre, les coûts de
> restauration, de communication de crise et de juristes sont couverts."

---

### **PAUSE - Temps de jeu cellule : 30 minutes**

**Consignes :**

1. **Débattre du paiement de la rançon**

2. **Évaluer le risque de fuite de données**

3. **Activer l'assurance**

4. **Mettre à jour le plan 72h**

**Livrables :**
- Décision motivée sur paiement rançon (argumentée)
- Analyse risque fuite données + plan de notification
- Déclaration sinistre assurance (synthèse)
- Planning 72h mis à jour

---

### Phase 5 : Retour à la normale (14h00)

**INJECT 9 - 14h00**

Bonne nouvelle de l'équipe IT :

> "La restauration des serveurs depuis les snapshots AWS progresse bien.
> On devrait pouvoir rouvrir les services en lecture seule à 18h, et en
> mode complet demain matin 8h.
>
> Par contre, on confirme que les données saisies entre vendredi 18h et
> dimanche 20h (moment de l'attaque) sont perdues. C'est environ 48h de
> consultations."

**INJECT 10 - 14h30**

Le CEO reçoit un appel de l'ANSSI (Agence Nationale de la Sécurité des Systèmes d'Information) :

> "Nous avons été informés de votre incident. En tant qu'hébergeur de données
> de santé et opérateur d'importance vitale potentiel, nous souhaitons être
> tenus informés de l'évolution. Un de nos experts peut vous assister si besoin."

---

### **PAUSE - Temps de jeu cellule : 20 minutes**

**Consignes :**

1. **Préparer le retour en production**

2. **Gérer la relation ANSSI**

3. **Anticiper l'après-crise**

**Livrables :**
- Message de réouverture aux clients
- FAQ support (top 10 questions attendues)
- 5 actions post-crise prioritaires

---

## Fin de la simulation - RETEX (30 min)

---

## Livrables à rendre

### 1. Main courante complète

Format Excel ou équivalent avec les colonnes :
- Horodatage
- Événement / Information
- Décision prise
- Responsable
- Action

### 2. Rapport de crise (2-3 pages)

Contenant :
- Synthèse de la crise
- Principales décisions et justifications
- Messages de communication produits
- Chronologie
- 5 leçons apprises
