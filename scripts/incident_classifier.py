#!/usr/bin/env python3
"""
Incident Classifier - Classification automatique des incidents de sécurité
Basé sur les critères NIST SP 800-61 et matrices de risque entreprise

Auteur: SOC Team
Version: 1.0
Date: 2024-01-15
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional
import hashlib


# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Niveaux de sévérité des incidents"""
    CRITICAL = 1  # P1 - Rouge
    HIGH = 2      # P2 - Orange
    MEDIUM = 3    # P3 - Jaune
    LOW = 4       # P4 - Vert

    def __str__(self):
        return self.name


class IncidentCategory(Enum):
    """Catégories d'incidents selon la taxonomie ENISA"""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_BREACH = "data_breach"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    ACCOUNT_COMPROMISE = "account_compromise"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    OTHER = "other"


class DataClassification(Enum):
    """Classification des données"""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4


class SystemCriticality(Enum):
    """Criticité des systèmes"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AffectedAsset:
    """Représente un asset affecté par l'incident"""
    hostname: str
    ip_address: str
    asset_type: str  # server, workstation, network_device, cloud_resource
    criticality: SystemCriticality
    owner: str
    department: str

    def to_dict(self) -> Dict:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "asset_type": self.asset_type,
            "criticality": self.criticality.name,
            "owner": self.owner,
            "department": self.department
        }


@dataclass
class IOC:
    """Indicateur de Compromission"""
    ioc_type: str  # ip, domain, hash_md5, hash_sha256, url, email, filename
    value: str
    context: str
    confidence: str  # high, medium, low
    source: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Incident:
    """Représente un incident de sécurité"""
    # Identification
    title: str
    description: str
    category: IncidentCategory
    source: str  # SIEM, EDR, User Report, Threat Intel, etc.

    # Impact
    affected_assets: List[AffectedAsset] = field(default_factory=list)
    affected_user_count: int = 0
    data_classification: DataClassification = DataClassification.INTERNAL
    data_volume_gb: float = 0.0
    personal_data_involved: bool = False

    # Risques
    business_critical: bool = False
    propagation_risk: bool = False
    active_threat: bool = False
    external_exposure: bool = False

    # IOCs
    iocs: List[IOC] = field(default_factory=list)

    # Métadonnées
    incident_id: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.now)
    reported_by: str = ""

    def __post_init__(self):
        if not self.incident_id:
            self.incident_id = self._generate_incident_id()

    def _generate_incident_id(self) -> str:
        """Génère un ID unique pour l'incident"""
        timestamp = self.detected_at.strftime("%Y%m%d%H%M%S")
        hash_input = f"{self.title}{timestamp}{self.category.value}"
        short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:6].upper()
        return f"INC-{self.detected_at.year}-{short_hash}"

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "source": self.source,
            "detected_at": self.detected_at.isoformat(),
            "reported_by": self.reported_by,
            "affected_assets": [a.to_dict() for a in self.affected_assets],
            "affected_user_count": self.affected_user_count,
            "data_classification": self.data_classification.name,
            "data_volume_gb": self.data_volume_gb,
            "personal_data_involved": self.personal_data_involved,
            "business_critical": self.business_critical,
            "propagation_risk": self.propagation_risk,
            "active_threat": self.active_threat,
            "external_exposure": self.external_exposure,
            "iocs": [ioc.to_dict() for ioc in self.iocs]
        }


@dataclass
class ClassificationResult:
    """Résultat de la classification d'un incident"""
    incident_id: str
    severity: Severity
    score: int
    factors: Dict[str, int]
    sla_response_minutes: int
    sla_containment_minutes: int
    escalation_required: bool
    escalation_contacts: List[str]
    recommended_actions: List[str]
    mitre_attack_techniques: List[str]

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity.name,
            "score": self.score,
            "factors": self.factors,
            "sla_response_minutes": self.sla_response_minutes,
            "sla_containment_minutes": self.sla_containment_minutes,
            "escalation_required": self.escalation_required,
            "escalation_contacts": self.escalation_contacts,
            "recommended_actions": self.recommended_actions,
            "mitre_attack_techniques": self.mitre_attack_techniques
        }


class IncidentClassifier:
    """
    Classifie automatiquement la sévérité des incidents de sécurité
    basé sur plusieurs critères pondérés.
    """

    # Configuration des poids pour chaque critère
    WEIGHTS = {
        "active_threat": 30,
        "ransomware": 25,
        "data_breach_personal": 25,
        "business_critical": 20,
        "propagation_risk": 15,
        "external_exposure": 15,
        "data_classification_restricted": 15,
        "data_classification_confidential": 10,
        "high_criticality_asset": 15,
        "critical_asset": 20,
        "high_user_count": 10,
        "large_data_volume": 10,
    }

    # Seuils de sévérité
    THRESHOLDS = {
        Severity.CRITICAL: 70,
        Severity.HIGH: 50,
        Severity.MEDIUM: 30,
        Severity.LOW: 0
    }

    # SLA par niveau de sévérité (en minutes)
    SLA = {
        Severity.CRITICAL: {"response": 15, "containment": 60},
        Severity.HIGH: {"response": 60, "containment": 240},
        Severity.MEDIUM: {"response": 240, "containment": 1440},
        Severity.LOW: {"response": 1440, "containment": 4320}
    }

    # Contacts d'escalade par niveau
    ESCALATION_CONTACTS = {
        Severity.CRITICAL: ["RSSI", "DSI", "Direction Générale", "DPO"],
        Severity.HIGH: ["RSSI", "SOC Manager"],
        Severity.MEDIUM: ["SOC Manager"],
        Severity.LOW: []
    }

    # Mapping catégorie -> techniques MITRE ATT&CK courantes
    MITRE_MAPPING = {
        IncidentCategory.RANSOMWARE: ["T1486", "T1490", "T1489"],
        IncidentCategory.PHISHING: ["T1566.001", "T1566.002"],
        IncidentCategory.MALWARE: ["T1059", "T1053", "T1547"],
        IncidentCategory.INTRUSION: ["T1190", "T1133", "T1078"],
        IncidentCategory.DATA_EXFILTRATION: ["T1048", "T1041", "T1567"],
        IncidentCategory.ACCOUNT_COMPROMISE: ["T1078", "T1110", "T1003"],
        IncidentCategory.DDOS: ["T1498", "T1499"],
        IncidentCategory.INSIDER_THREAT: ["T1078", "T1530"],
    }

    # Actions recommandées par catégorie
    RECOMMENDED_ACTIONS = {
        IncidentCategory.RANSOMWARE: [
            "Isoler immédiatement les systèmes affectés du réseau",
            "NE PAS éteindre les machines (préservation mémoire)",
            "Vérifier l'intégrité des sauvegardes",
            "Identifier le vecteur d'infection initial",
            "Bloquer les IOCs sur le périmètre",
            "Activer la cellule de crise si P1"
        ],
        IncidentCategory.PHISHING: [
            "Quarantaine de l'email malveillant",
            "Identifier tous les destinataires",
            "Vérifier les clics sur les liens",
            "Reset des credentials si compromission",
            "Scan des postes des victimes",
            "Communication de sensibilisation"
        ],
        IncidentCategory.DATA_BREACH: [
            "Identifier l'étendue de la fuite",
            "Préserver les preuves",
            "Évaluer l'obligation de notification CNIL",
            "Bloquer l'accès non autorisé",
            "Investiguer la source de la fuite"
        ],
        IncidentCategory.ACCOUNT_COMPROMISE: [
            "Désactiver le compte compromis",
            "Reset du mot de passe",
            "Révoquer les sessions actives",
            "Vérifier les actions effectuées",
            "Analyser les logs d'authentification",
            "Vérifier les connexions latérales"
        ],
        IncidentCategory.MALWARE: [
            "Isoler le système infecté",
            "Acquisition mémoire si possible",
            "Identifier la famille de malware",
            "Rechercher la propagation",
            "Extraire et bloquer les IOCs"
        ],
        IncidentCategory.DDOS: [
            "Activer les protections anti-DDoS",
            "Contacter le FAI/CDN",
            "Identifier les sources d'attaque",
            "Mettre en place le filtrage",
            "Communiquer sur l'indisponibilité"
        ]
    }

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def classify(self, incident: Incident) -> ClassificationResult:
        """
        Classifie un incident et retourne le résultat complet.

        Args:
            incident: L'incident à classifier

        Returns:
            ClassificationResult avec la sévérité et les recommandations
        """
        self.logger.info(f"Classification de l'incident: {incident.incident_id}")

        # Calculer le score
        score, factors = self._calculate_score(incident)

        # Déterminer la sévérité
        severity = self._determine_severity(score)

        # Obtenir les SLA
        sla = self.SLA[severity]

        # Déterminer l'escalade
        escalation_required = severity in [Severity.CRITICAL, Severity.HIGH]
        escalation_contacts = self.ESCALATION_CONTACTS[severity]

        # Obtenir les actions recommandées
        recommended_actions = self._get_recommended_actions(incident)

        # Mapper les techniques MITRE
        mitre_techniques = self.MITRE_MAPPING.get(incident.category, [])

        result = ClassificationResult(
            incident_id=incident.incident_id,
            severity=severity,
            score=score,
            factors=factors,
            sla_response_minutes=sla["response"],
            sla_containment_minutes=sla["containment"],
            escalation_required=escalation_required,
            escalation_contacts=escalation_contacts,
            recommended_actions=recommended_actions,
            mitre_attack_techniques=mitre_techniques
        )

        self.logger.info(f"Résultat: Sévérité={severity.name}, Score={score}")

        return result

    def _calculate_score(self, incident: Incident) -> tuple:
        """Calcule le score de l'incident basé sur les critères pondérés."""
        score = 0
        factors = {}

        # Menace active
        if incident.active_threat:
            points = self.WEIGHTS["active_threat"]
            score += points
            factors["active_threat"] = points

        # Ransomware (catégorie spéciale)
        if incident.category == IncidentCategory.RANSOMWARE:
            points = self.WEIGHTS["ransomware"]
            score += points
            factors["ransomware"] = points

        # Données personnelles impliquées
        if incident.personal_data_involved:
            points = self.WEIGHTS["data_breach_personal"]
            score += points
            factors["personal_data"] = points

        # Système critique pour le business
        if incident.business_critical:
            points = self.WEIGHTS["business_critical"]
            score += points
            factors["business_critical"] = points

        # Risque de propagation
        if incident.propagation_risk:
            points = self.WEIGHTS["propagation_risk"]
            score += points
            factors["propagation_risk"] = points

        # Exposition externe
        if incident.external_exposure:
            points = self.WEIGHTS["external_exposure"]
            score += points
            factors["external_exposure"] = points

        # Classification des données
        if incident.data_classification == DataClassification.RESTRICTED:
            points = self.WEIGHTS["data_classification_restricted"]
            score += points
            factors["data_restricted"] = points
        elif incident.data_classification == DataClassification.CONFIDENTIAL:
            points = self.WEIGHTS["data_classification_confidential"]
            score += points
            factors["data_confidential"] = points

        # Criticité des assets
        for asset in incident.affected_assets:
            if asset.criticality == SystemCriticality.CRITICAL:
                points = self.WEIGHTS["critical_asset"]
                score += points
                factors[f"critical_asset_{asset.hostname}"] = points
                break  # Compter une seule fois
            elif asset.criticality == SystemCriticality.HIGH:
                points = self.WEIGHTS["high_criticality_asset"]
                score += points
                factors[f"high_criticality_asset_{asset.hostname}"] = points
                break

        # Nombre d'utilisateurs affectés
        if incident.affected_user_count > 100:
            points = self.WEIGHTS["high_user_count"]
            score += points
            factors["high_user_count"] = points

        # Volume de données
        if incident.data_volume_gb > 100:
            points = self.WEIGHTS["large_data_volume"]
            score += points
            factors["large_data_volume"] = points

        return score, factors

    def _determine_severity(self, score: int) -> Severity:
        """Détermine la sévérité basée sur le score."""
        if score >= self.THRESHOLDS[Severity.CRITICAL]:
            return Severity.CRITICAL
        elif score >= self.THRESHOLDS[Severity.HIGH]:
            return Severity.HIGH
        elif score >= self.THRESHOLDS[Severity.MEDIUM]:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _get_recommended_actions(self, incident: Incident) -> List[str]:
        """Retourne les actions recommandées pour la catégorie d'incident."""
        actions = self.RECOMMENDED_ACTIONS.get(
            incident.category,
            ["Analyser l'incident", "Documenter les observations", "Escalader si nécessaire"]
        )
        return actions.copy()


def create_sample_incident() -> Incident:
    """Crée un incident d'exemple pour démonstration."""

    # Assets affectés
    assets = [
        AffectedAsset(
            hostname="WKS-COMPTA-01",
            ip_address="192.168.10.50",
            asset_type="workstation",
            criticality=SystemCriticality.MEDIUM,
            owner="Jean Dupont",
            department="Comptabilité"
        ),
        AffectedAsset(
            hostname="SRV-FILE-01",
            ip_address="192.168.5.10",
            asset_type="server",
            criticality=SystemCriticality.HIGH,
            owner="IT Operations",
            department="IT"
        )
    ]

    # IOCs
    iocs = [
        IOC(
            ioc_type="ip",
            value="185.234.72.100",
            context="Serveur C2",
            confidence="high",
            source="Memory forensics"
        ),
        IOC(
            ioc_type="hash_sha256",
            value="a1b2c3d4e5f6...",
            context="Payload ransomware",
            confidence="high",
            source="Disk analysis"
        ),
        IOC(
            ioc_type="domain",
            value="malware-update.net",
            context="Distribution serveur",
            confidence="high",
            source="Network logs"
        )
    ]

    # Création de l'incident
    incident = Incident(
        title="Ransomware LockBit détecté sur serveur de fichiers",
        description="Activité de chiffrement anormale détectée sur SRV-FILE-01. "
                    "Plusieurs fichiers avec extension .lockbit identifiés. "
                    "Note de rançon présente.",
        category=IncidentCategory.RANSOMWARE,
        source="SIEM - Règle CORR-006",
        affected_assets=assets,
        affected_user_count=150,
        data_classification=DataClassification.CONFIDENTIAL,
        data_volume_gb=500,
        personal_data_involved=True,
        business_critical=True,
        propagation_risk=True,
        active_threat=True,
        external_exposure=False,
        iocs=iocs,
        reported_by="SOC L1 - Alert Monitor"
    )

    return incident


def main():
    """Fonction principale de démonstration."""

    print("=" * 70)
    print("INCIDENT CLASSIFIER - Démonstration")
    print("=" * 70)
    print()

    # Créer un incident d'exemple
    incident = create_sample_incident()

    print(f"Incident créé: {incident.incident_id}")
    print(f"Titre: {incident.title}")
    print(f"Catégorie: {incident.category.value}")
    print(f"Assets affectés: {len(incident.affected_assets)}")
    print()

    # Classifier l'incident
    classifier = IncidentClassifier()
    result = classifier.classify(incident)

    # Afficher les résultats
    print("=" * 70)
    print("RÉSULTAT DE LA CLASSIFICATION")
    print("=" * 70)
    print()

    print(f"{'Sévérité:':<25} {result.severity.name} (P{result.severity.value})")
    print(f"{'Score:':<25} {result.score}/100")
    print(f"{'SLA Réponse:':<25} {result.sla_response_minutes} minutes")
    print(f"{'SLA Confinement:':<25} {result.sla_containment_minutes} minutes")
    print(f"{'Escalade requise:':<25} {'Oui' if result.escalation_required else 'Non'}")
    print()

    print("Facteurs de scoring:")
    for factor, points in result.factors.items():
        print(f"  - {factor}: +{points} points")
    print()

    if result.escalation_contacts:
        print("Contacts d'escalade:")
        for contact in result.escalation_contacts:
            print(f"  - {contact}")
        print()

    print("Actions recommandées:")
    for i, action in enumerate(result.recommended_actions, 1):
        print(f"  {i}. {action}")
    print()

    if result.mitre_attack_techniques:
        print("Techniques MITRE ATT&CK:")
        for technique in result.mitre_attack_techniques:
            print(f"  - {technique}")
        print()

    # Export JSON
    print("=" * 70)
    print("EXPORT JSON")
    print("=" * 70)
    print()

    export_data = {
        "incident": incident.to_dict(),
        "classification": result.to_dict()
    }

    print(json.dumps(export_data, indent=2, default=str))


if __name__ == "__main__":
    main()
