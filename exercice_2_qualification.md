# Exercice 01 : Qualification d'incidents de sécurité

## Informations pratiques

| Élément | Valeur |
|---------|--------|
| **Durée** | 30 minutes (travail individuel) |
| **Mode** | Individuel |
| **Livrable** | Tableau de qualification complété |
| **Support** | Grille de criticité ANSSI |

---

## Objectifs pédagogiques

À l'issue de cet exercice, vous serez capable de :
1. Qualifier un événement de sécurité selon la grille ANSSI
2. Distinguer incident mineur, majeur et crise
3. Proposer une première réponse adaptée
4. Identifier les parties prenantes à alerter

---

## Contexte

Vous êtes analyste SOC dans une entreprise de taille moyenne (500 employés, secteur bancaire). Il est **mardi 10h30**, et vous recevez plusieurs alertes et signalements.

Votre mission : **qualifier chacun des 5 événements** ci-dessous et proposer une première réponse.

---

## Grille de criticité ANSSI (rappel)

| Niveau | Nom | Critères | Exemples |
|--------|-----|----------|----------|
| **4** | Crise | Impact critique + médiatisation OU perte de données sensibles massives OU arrêt activité > 24h | Ransomware, APT, fuite massive |
| **3** | Majeur | Impact significatif sur le métier OU données sensibles exposées | Compromission serveur, défacement |
| **2** | Mineur | Impact limité, pas de données sensibles | Malware isolé, tentative bloquée |
| **1** | Événement | Détection, pas d'impact | Scan réseau, faux positif |

---

## Événement 1 : Phishing signalé

### Contexte
**Mardi 09h15** : Un collaborateur du service RH signale avoir reçu un email suspect se faisant passer pour le DRH. L'email demande de télécharger une pièce jointe "Planning_2024.xlsx" et de fournir la liste des employés avec leurs emails.

**Informations complémentaires** :
- Le collaborateur **n'a pas ouvert** la pièce jointe
- Il a transféré l'email au support IT
- L'email provient d'une adresse externe : `drh.direction@entreprise-fr.com` (notre domaine réel : `entreprise.fr`)
- Analyse antivirus de la pièce jointe : **Trojan.GenericKD.12345678 détecté**

### Questions

1. **Niveau de criticité** : [1 / 2 / 3 / 4] - Justifiez
2. **Type d'incident** : [Phishing / Malware / Compromission / Autre]
3. **Impact potentiel** : [Décrivez]
4. **Première réponse** : Listez les 3 premières actions à mener
5. **Qui alerter** : [Internes / Externes / Autorités]

---

## Événement 2 : Serveur web défacé

### Contexte
**Mardi 10h00** : Le service marketing vous appelle : le site vitrine de l'entreprise (www.entreprise.fr) affiche un message inhabituel avec le logo d'un groupe de hackers.

**Informations complémentaires** :
- Le site vitrine est hébergé chez un prestataire externe
- Aucune donnée client n'est stockée sur ce serveur (site purement informatif)
- Le message affiché : "Hacked by Anonymous - Your security is a joke"
- Trafic du site : ~2 000 visiteurs/jour
- Aucune donnée sensible sur ce serveur
- Le site corporate principal (clients, comptes) est sur une infrastructure séparée et **n'est pas affecté**

### Questions

1. **Niveau de criticité** : [1 / 2 / 3 / 4] - Justifiez
2. **Type d'incident** : [Défacement / Compromission / DDoS / Autre]
3. **Impact métier** : [Décrivez en termes business]
4. **Première réponse** : Actions immédiates (priorisées)
5. **Communication** : Devez-vous communiquer ? À qui ?

---

## Événement 3 : Détection EDR - Mouvement latéral

### Contexte
**Mardi 10h15** : Votre EDR (Endpoint Detection & Response) remonte une alerte **HIGH** :

```
ALERT: Lateral Movement Detected
Host: WKS-FINANCE-042 (PC de Marie DUPONT, Contrôleuse de gestion)
Process: powershell.exe
Command: Invoke-Mimikatz -DumpCreds
Destination: SRV-FIN-01 (Serveur de fichiers Finance)
Time: 10:12:34
Status: BLOCKED by EDR
```

**Informations complémentaires** :
- Marie DUPONT est actuellement en **congés** (absente depuis lundi)
- Son PC devrait être éteint
- Le serveur SRV-FIN-01 contient des données comptables sensibles
- L'EDR a bloqué l'exécution de Mimikatz
- Connexion réseau active depuis WKS-FINANCE-042 vers plusieurs autres machines du réseau

### Questions

1. **Niveau de criticité** : [1 / 2 / 3 / 4] - Justifiez
2. **Type d'incident** : [Vol de credentials / Ransomware / Mouvement latéral / APT]
3. **Hypothèses sur le vecteur initial** : [Comment le poste a-t-il pu être compromis ?]
4. **Actions immédiates** : Quelles sont vos 5 premières actions ?
5. **Escalade** : Qui devez-vous impérativement informer dans l'entreprise ?

---

## Événement 4 : Tentative de connexion administrative

### Contexte
**Mardi 10h25** : Les logs du firewall montrent des tentatives de connexion SSH répétées sur votre serveur de production depuis une IP chinoise.

```
LOG EXTRACT:
10:20:15 | SSH AUTH FAILED | root | 112.90.34.56 | SRV-PROD-01
10:20:18 | SSH AUTH FAILED | admin | 112.90.34.56 | SRV-PROD-01
10:20:21 | SSH AUTH FAILED | root | 112.90.34.56 | SRV-PROD-01
[... 847 tentatives en 10 minutes ...]
10:30:45 | SSH AUTH FAILED | root | 112.90.34.56 | SRV-PROD-01
```

**Informations complémentaires** :
- Total : **847 tentatives** en 10 minutes
- Aucune tentative réussie
- Le serveur utilise une authentification par clé SSH (pas de mot de passe)
- Le port SSH (22) est exposé sur internet (legacy, migration plannifiée)
- Aucun autre comportement anormal détecté

### Questions

1. **Niveau de criticité** : [1 / 2 / 3 / 4] - Justifiez
2. **Type d'attaque** : [Bruteforce / DDoS / Scan / APT]
3. **Risque réel** : [Évaluez le risque compte tenu du contexte]
4. **Actions recommandées** : Court terme et moyen terme
5. **Faut-il escalader ?** : [Oui/Non] - Pourquoi ?

---

## Événement 5 : Fuite de données suspectée

### Contexte
**Mardi 10h30** : Le DPO (Data Protection Officer) vous transfère un email anonyme reçu sur l'adresse générique `contact@entreprise.fr` :

```
Subject: You've been breached

We have accessed your customer database (15,000 records).
Customers names, emails, phone numbers, IBAN.

We will publish everything on dark web if you don't pay 50 BTC
within 72 hours.

Proof attached: sample.csv (100 first records)

Bitcoin address: [...]
```

**Informations complémentaires** :
- Le fichier `sample.csv` contient effectivement 100 lignes avec :
  - Noms de clients **réels**
  - Emails **corrects**
  - Numéros de téléphone **corrects**
  - IBAN **partiellement masqués** (mais cohérents)
- Ces données datent de **moins de 3 mois**
- Vous n'avez **pas encore identifié** la source de la fuite
- Votre base clients contient effectivement ~15 000 entrées
- Secteur bancaire → Données financières sensibles

### Questions

1. **Niveau de criticité** : [1 / 2 / 3 / 4] - Justifiez
2. **Type d'incident** : [Fuite de données / Ransomware / Extorsion / APT]
3. **Obligations légales** : Quelles sont vos obligations RGPD ?
4. **Actions urgentes (< 1h)** : Listez par ordre de priorité
5. **Qui impliquer** : Interne et externe (CNIL, ANSSI, etc.)

---

## Tableau de synthèse à compléter

| Événement | Criticité (1-4) | Type incident | Impact | Actions immédiates (top 3) | Escalade |
|-----------|----------------|---------------|--------|---------------------------|----------|
| 1. Phishing | | | | 1.<br>2.<br>3. | |
| 2. Défacement | | | | 1.<br>2.<br>3. | |
| 3. Mouvement latéral | | | | 1.<br>2.<br>3. | |
| 4. Bruteforce SSH | | | | 1.<br>2.<br>3. | |
| 5. Fuite de données | | | | 1.<br>2.<br>3. | |

---

## Questions bonus (optionnelles)

### Question A : Priorisation

Vous ne pouvez traiter qu'**un seul événement** en priorité dans l'heure qui vient. Lequel choisissez-vous et pourquoi ?

**Réponse** :
[Votre réponse ici]

---

### Question B : Ressources

Vous avez besoin de renfort. Vous pouvez appeler :
- L'équipe IT (3 personnes)
- Le RSSI
- Un prestataire externe (forensics)
- La direction

Pour **quel(s) événement(s)** et dans **quel ordre** les mobilisez-vous ?

**Réponse** :
[Votre réponse ici]
