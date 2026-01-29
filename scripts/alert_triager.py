#!/usr/bin/env python3
"""
Alert Triager - Système de triage automatisé des alertes SIEM
Intègre enrichissement CTI et classification automatique

Auteur: SOC Team
Version: 1.0
Date: 2024-01-15

Fonctionnalités:
- Extraction automatique des IOCs
- Enrichissement via VirusTotal, AbuseIPDB, MISP
- Classification de sévérité
- Génération de tickets TheHive
"""

import re
import json
import hashlib
import logging
import requests
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from enum import Enum
import ipaddress
from abc import ABC, abstractmethod


# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IOCType(Enum):
    """Types d'Indicateurs de Compromission"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILENAME = "filename"
    UNKNOWN = "unknown"


class AlertStatus(Enum):
    """Statuts possibles d'une alerte"""
    NEW = "new"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class Severity(Enum):
    """Niveaux de sévérité"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class ExtractedIOC:
    """IOC extrait d'une alerte"""
    ioc_type: IOCType
    value: str
    context: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "context": self.context
        }


@dataclass
class EnrichmentResult:
    """Résultat d'enrichissement d'un IOC"""
    ioc_value: str
    ioc_type: IOCType
    source: str
    is_malicious: bool
    confidence: str  # high, medium, low
    details: Dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "ioc": self.ioc_value,
            "type": self.ioc_type.value,
            "source": self.source,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "details": self.details,
            "error": self.error
        }


@dataclass
class Alert:
    """Représente une alerte SIEM"""
    alert_id: str
    title: str
    description: str
    source: str
    timestamp: datetime
    raw_log: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    severity_original: str = "medium"
    rule_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "raw_log": self.raw_log,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "user": self.user,
            "hostname": self.hostname,
            "severity_original": self.severity_original,
            "rule_id": self.rule_id,
            "tags": self.tags
        }


@dataclass
class TriageResult:
    """Résultat complet du triage d'une alerte"""
    alert_id: str
    status: AlertStatus
    severity: Severity
    timestamp: datetime
    extracted_iocs: List[ExtractedIOC]
    enrichments: List[EnrichmentResult]
    is_false_positive: bool
    false_positive_reason: Optional[str]
    recommended_action: str
    analyst_notes: str
    escalate: bool
    escalate_to: List[str]
    mitre_techniques: List[str]

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "status": self.status.value,
            "severity": self.severity.name,
            "timestamp": self.timestamp.isoformat(),
            "extracted_iocs": [ioc.to_dict() for ioc in self.extracted_iocs],
            "enrichments": [e.to_dict() for e in self.enrichments],
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "recommended_action": self.recommended_action,
            "analyst_notes": self.analyst_notes,
            "escalate": self.escalate,
            "escalate_to": self.escalate_to,
            "mitre_techniques": self.mitre_techniques
        }


class IOCExtractor:
    """Extracteur d'IOCs à partir de texte"""

    # Patterns regex pour extraction
    PATTERNS = {
        IOCType.IP: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        IOCType.DOMAIN: r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        IOCType.URL: r'https?://[^\s<>"{}|\\^`\[\]]+',
        IOCType.HASH_MD5: r'\b[a-fA-F0-9]{32}\b',
        IOCType.HASH_SHA1: r'\b[a-fA-F0-9]{40}\b',
        IOCType.HASH_SHA256: r'\b[a-fA-F0-9]{64}\b',
        IOCType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    }

    # IPs/domaines à ignorer (internes, localhost, etc.)
    WHITELIST_IPS = [
        '127.0.0.1', '0.0.0.0', '255.255.255.255',
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
    ]

    WHITELIST_DOMAINS = [
        'localhost', 'example.com', 'test.com',
        'microsoft.com', 'windows.com', 'google.com',
        'googleapis.com', 'gstatic.com'
    ]

    def extract_all(self, text: str) -> List[ExtractedIOC]:
        """Extrait tous les IOCs d'un texte."""
        iocs = []

        for ioc_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Filtrer les faux positifs
                if self._should_include(match, ioc_type):
                    iocs.append(ExtractedIOC(
                        ioc_type=ioc_type,
                        value=match.lower() if ioc_type != IOCType.IP else match,
                        context=self._extract_context(text, match)
                    ))

        # Dédupliquer
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs

    def _should_include(self, value: str, ioc_type: IOCType) -> bool:
        """Vérifie si l'IOC doit être inclus (pas dans whitelist)."""

        if ioc_type == IOCType.IP:
            # Vérifier si IP privée ou localhost
            try:
                ip = ipaddress.ip_address(value)
                if ip.is_private or ip.is_loopback or ip.is_multicast:
                    return False
            except ValueError:
                return False

        elif ioc_type == IOCType.DOMAIN:
            # Vérifier whitelist domaines
            for whitelisted in self.WHITELIST_DOMAINS:
                if value.lower().endswith(whitelisted):
                    return False

        return True

    def _extract_context(self, text: str, match: str, context_chars: int = 50) -> str:
        """Extrait le contexte autour d'un match."""
        idx = text.lower().find(match.lower())
        if idx == -1:
            return ""

        start = max(0, idx - context_chars)
        end = min(len(text), idx + len(match) + context_chars)

        context = text[start:end]
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."

        return context


class ThreatIntelProvider(ABC):
    """Interface pour les fournisseurs de Threat Intelligence"""

    @abstractmethod
    def enrich(self, ioc: ExtractedIOC) -> EnrichmentResult:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class VirusTotalProvider(ThreatIntelProvider):
    """Enrichissement via VirusTotal API"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    def get_name(self) -> str:
        return "VirusTotal"

    def enrich(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Enrichit un IOC via VirusTotal."""

        try:
            if ioc.ioc_type == IOCType.IP:
                return self._check_ip(ioc)
            elif ioc.ioc_type == IOCType.DOMAIN:
                return self._check_domain(ioc)
            elif ioc.ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                return self._check_hash(ioc)
            else:
                return EnrichmentResult(
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source=self.get_name(),
                    is_malicious=False,
                    confidence="low",
                    error="IOC type not supported"
                )
        except Exception as e:
            logger.error(f"Erreur VirusTotal pour {ioc.value}: {e}")
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error=str(e)
            )

    def _check_ip(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Vérifie une IP sur VirusTotal."""
        url = f"{self.base_url}/ip_addresses/{ioc.value}"
        response = requests.get(url, headers=self.headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            is_malicious = (malicious + suspicious) > 3
            confidence = "high" if total > 50 else "medium" if total > 20 else "low"

            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=is_malicious,
                confidence=confidence,
                details={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0)
                }
            )
        else:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error=f"HTTP {response.status_code}"
            )

    def _check_domain(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Vérifie un domaine sur VirusTotal."""
        url = f"{self.base_url}/domains/{ioc.value}"
        response = requests.get(url, headers=self.headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            is_malicious = (malicious + suspicious) > 3

            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=is_malicious,
                confidence="high" if is_malicious else "medium",
                details={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "categories": data.get("data", {}).get("attributes", {}).get("categories", {})
                }
            )
        else:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error=f"HTTP {response.status_code}"
            )

    def _check_hash(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Vérifie un hash sur VirusTotal."""
        url = f"{self.base_url}/files/{ioc.value}"
        response = requests.get(url, headers=self.headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            is_malicious = malicious > 5

            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=is_malicious,
                confidence="high" if total > 50 else "medium",
                details={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "type_description": data.get("data", {}).get("attributes", {}).get("type_description", ""),
                    "names": data.get("data", {}).get("attributes", {}).get("names", [])[:5]
                }
            )
        elif response.status_code == 404:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                details={"status": "not_found"}
            )
        else:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error=f"HTTP {response.status_code}"
            )


class AbuseIPDBProvider(ThreatIntelProvider):
    """Enrichissement via AbuseIPDB API"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

    def get_name(self) -> str:
        return "AbuseIPDB"

    def enrich(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Enrichit un IOC via AbuseIPDB (IPs uniquement)."""

        if ioc.ioc_type != IOCType.IP:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error="Only IP addresses supported"
            )

        try:
            url = f"{self.base_url}/check"
            params = {
                "ipAddress": ioc.value,
                "maxAgeInDays": 90
            }
            response = requests.get(url, headers=self.headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)

                is_malicious = abuse_score > 50
                confidence = "high" if total_reports > 10 else "medium" if total_reports > 3 else "low"

                return EnrichmentResult(
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source=self.get_name(),
                    is_malicious=is_malicious,
                    confidence=confidence,
                    details={
                        "abuse_score": abuse_score,
                        "total_reports": total_reports,
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "domain": data.get("domain", ""),
                        "is_tor": data.get("isTor", False),
                        "usage_type": data.get("usageType", "")
                    }
                )
            else:
                return EnrichmentResult(
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    source=self.get_name(),
                    is_malicious=False,
                    confidence="low",
                    error=f"HTTP {response.status_code}"
                )
        except Exception as e:
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=False,
                confidence="low",
                error=str(e)
            )


class MockThreatIntelProvider(ThreatIntelProvider):
    """Provider mock pour les tests/démonstrations"""

    KNOWN_BAD = {
        "185.234.72.100": {"malicious": True, "confidence": "high", "reason": "Known C2 server"},
        "91.215.85.142": {"malicious": True, "confidence": "high", "reason": "Malware distribution"},
        "malware-c2.evil.com": {"malicious": True, "confidence": "high", "reason": "C2 domain"},
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4": {"malicious": True, "confidence": "high", "reason": "Known malware"}
    }

    def get_name(self) -> str:
        return "MockThreatIntel"

    def enrich(self, ioc: ExtractedIOC) -> EnrichmentResult:
        """Retourne un résultat mock."""

        if ioc.value in self.KNOWN_BAD:
            info = self.KNOWN_BAD[ioc.value]
            return EnrichmentResult(
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                source=self.get_name(),
                is_malicious=info["malicious"],
                confidence=info["confidence"],
                details={"reason": info["reason"]}
            )

        return EnrichmentResult(
            ioc_value=ioc.value,
            ioc_type=ioc.ioc_type,
            source=self.get_name(),
            is_malicious=False,
            confidence="medium",
            details={"status": "not_found_in_database"}
        )


class AlertTriager:
    """
    Système de triage automatisé des alertes SIEM.

    Processus:
    1. Extraction des IOCs
    2. Enrichissement via CTI
    3. Classification de sévérité
    4. Génération des recommandations
    """

    # Règles SIEM connues et leur sévérité de base
    RULE_SEVERITY = {
        "CORR-001": Severity.HIGH,    # Brute force
        "CORR-002": Severity.HIGH,    # Admin hors heures
        "CORR-003": Severity.CRITICAL, # PowerShell encodé
        "CORR-004": Severity.HIGH,    # Exfiltration
        "CORR-005": Severity.HIGH,    # Scheduled task suspecte
        "CORR-006": Severity.CRITICAL, # Ransomware
        "CORR-007": Severity.CRITICAL, # C2 connu
    }

    # Mots-clés qui augmentent la sévérité
    HIGH_SEVERITY_KEYWORDS = [
        "ransomware", "lockbit", "ryuk", "conti",
        "mimikatz", "cobalt", "metasploit",
        "exfiltration", "c2", "command and control",
        "privilege escalation", "lateral movement",
        "domain admin", "enterprise admin"
    ]

    def __init__(self, providers: List[ThreatIntelProvider] = None):
        self.ioc_extractor = IOCExtractor()
        self.providers = providers or [MockThreatIntelProvider()]
        self.logger = logging.getLogger(self.__class__.__name__)

    def triage(self, alert: Alert) -> TriageResult:
        """
        Effectue le triage complet d'une alerte.

        Args:
            alert: L'alerte à trier

        Returns:
            TriageResult avec tous les détails
        """
        self.logger.info(f"Début triage alerte: {alert.alert_id}")

        # 1. Extraction des IOCs
        all_text = f"{alert.title} {alert.description} {alert.raw_log}"
        if alert.source_ip:
            all_text += f" {alert.source_ip}"
        if alert.dest_ip:
            all_text += f" {alert.dest_ip}"

        extracted_iocs = self.ioc_extractor.extract_all(all_text)
        self.logger.info(f"IOCs extraits: {len(extracted_iocs)}")

        # 2. Enrichissement
        enrichments = []
        for ioc in extracted_iocs:
            for provider in self.providers:
                result = provider.enrich(ioc)
                enrichments.append(result)

        # 3. Analyse et classification
        severity, is_malicious_found = self._classify(alert, extracted_iocs, enrichments)

        # 4. Détection faux positif
        is_fp, fp_reason = self._check_false_positive(alert, enrichments)

        # 5. Recommandations
        action = self._get_recommended_action(alert, severity, is_malicious_found)

        # 6. Mapping MITRE
        mitre_techniques = self._map_mitre(alert)

        # 7. Escalade
        escalate = severity in [Severity.CRITICAL, Severity.HIGH] and not is_fp
        escalate_to = self._get_escalation_contacts(severity)

        # Notes d'analyste automatiques
        notes = self._generate_notes(alert, extracted_iocs, enrichments)

        result = TriageResult(
            alert_id=alert.alert_id,
            status=AlertStatus.FALSE_POSITIVE if is_fp else AlertStatus.TRIAGED,
            severity=severity,
            timestamp=datetime.now(),
            extracted_iocs=extracted_iocs,
            enrichments=enrichments,
            is_false_positive=is_fp,
            false_positive_reason=fp_reason,
            recommended_action=action,
            analyst_notes=notes,
            escalate=escalate,
            escalate_to=escalate_to,
            mitre_techniques=mitre_techniques
        )

        self.logger.info(f"Triage terminé: Sévérité={severity.name}, FP={is_fp}")

        return result

    def _classify(self, alert: Alert, iocs: List[ExtractedIOC],
                  enrichments: List[EnrichmentResult]) -> Tuple[Severity, bool]:
        """Détermine la sévérité de l'alerte."""

        # Sévérité de base depuis la règle SIEM
        base_severity = self.RULE_SEVERITY.get(alert.rule_id, Severity.MEDIUM)

        # Vérifier si des IOCs sont malveillants
        malicious_count = sum(1 for e in enrichments if e.is_malicious)
        is_malicious_found = malicious_count > 0

        # Ajuster la sévérité
        severity_value = base_severity.value

        if is_malicious_found:
            severity_value = min(severity_value, Severity.HIGH.value)
            if malicious_count >= 3:
                severity_value = Severity.CRITICAL.value

        # Vérifier les mots-clés critiques
        alert_text = f"{alert.title} {alert.description}".lower()
        for keyword in self.HIGH_SEVERITY_KEYWORDS:
            if keyword in alert_text:
                severity_value = min(severity_value, Severity.HIGH.value)
                break

        return Severity(severity_value), is_malicious_found

    def _check_false_positive(self, alert: Alert,
                               enrichments: List[EnrichmentResult]) -> Tuple[bool, Optional[str]]:
        """Vérifie si l'alerte est un faux positif probable."""

        # Logique de détection des FP
        # (à personnaliser selon l'environnement)

        # Exemple: si aucun IOC n'est malveillant et source interne connue
        malicious = [e for e in enrichments if e.is_malicious]

        if not malicious:
            # Vérifier si c'est une activité admin connue
            if alert.user and alert.user.lower() in ["admin", "svc_backup", "system"]:
                if "scheduled" in alert.title.lower() or "backup" in alert.title.lower():
                    return True, "Activité d'administration planifiée"

        return False, None

    def _get_recommended_action(self, alert: Alert, severity: Severity,
                                 is_malicious: bool) -> str:
        """Génère l'action recommandée."""

        if severity == Severity.CRITICAL:
            return "ESCALADE IMMÉDIATE - Contacter le SOC Manager et isoler les systèmes affectés"
        elif severity == Severity.HIGH:
            if is_malicious:
                return "Investigation approfondie requise - Bloquer les IOCs et analyser les systèmes"
            return "Investigation requise - Vérifier les logs associés et valider le contexte"
        elif severity == Severity.MEDIUM:
            return "Analyser le contexte - Vérifier si l'activité est légitime"
        else:
            return "Documenter et clôturer - Activité probablement bénigne"

    def _map_mitre(self, alert: Alert) -> List[str]:
        """Mappe l'alerte aux techniques MITRE ATT&CK."""
        techniques = []

        alert_lower = f"{alert.title} {alert.description}".lower()

        mappings = {
            "brute force": ["T1110"],
            "phishing": ["T1566"],
            "powershell": ["T1059.001"],
            "scheduled task": ["T1053.005"],
            "lateral movement": ["T1021"],
            "credential": ["T1003"],
            "exfiltration": ["T1048"],
            "ransomware": ["T1486"],
            "c2": ["T1071"],
        }

        for keyword, techs in mappings.items():
            if keyword in alert_lower:
                techniques.extend(techs)

        return list(set(techniques))

    def _get_escalation_contacts(self, severity: Severity) -> List[str]:
        """Retourne les contacts d'escalade selon la sévérité."""
        contacts = {
            Severity.CRITICAL: ["SOC Manager", "RSSI", "On-Call IR"],
            Severity.HIGH: ["SOC Manager"],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: []
        }
        return contacts.get(severity, [])

    def _generate_notes(self, alert: Alert, iocs: List[ExtractedIOC],
                        enrichments: List[EnrichmentResult]) -> str:
        """Génère les notes d'analyse automatiques."""
        notes = []

        notes.append(f"Alerte source: {alert.source}")
        notes.append(f"Règle: {alert.rule_id or 'N/A'}")
        notes.append(f"IOCs extraits: {len(iocs)}")

        malicious = [e for e in enrichments if e.is_malicious]
        if malicious:
            notes.append(f"IOCs malveillants détectés: {len(malicious)}")
            for m in malicious[:3]:
                notes.append(f"  - {m.ioc_value} ({m.source}: {m.confidence})")

        return "\n".join(notes)


def create_sample_alert() -> Alert:
    """Crée une alerte d'exemple pour démonstration."""

    raw_log = """
    2024-01-15T14:23:45.123Z host=SRV-FILE-01 user=svc_backup
    EventType=FileModification FilesModified=1847 TimeWindow=5min
    ProcessName=svchost32.exe ProcessPath=C:\\Windows\\Temp\\svchost32.exe
    ParentProcess=powershell.exe CommandLine="powershell -enc JABjAGw..."
    NetworkConnection=185.234.72.100:443
    """

    return Alert(
        alert_id="ALERT-2024-00142",
        title="Volume anormal de modifications de fichiers détecté",
        description="Plus de 1800 fichiers modifiés en 5 minutes sur SRV-FILE-01. "
                    "Processus suspect svchost32.exe avec connexion réseau externe. "
                    "Possible activité ransomware.",
        source="SIEM - Splunk",
        timestamp=datetime.now(),
        raw_log=raw_log,
        source_ip="192.168.5.10",
        dest_ip="185.234.72.100",
        user="svc_backup",
        hostname="SRV-FILE-01",
        severity_original="high",
        rule_id="CORR-006",
        tags=["ransomware", "file_modification", "network_connection"]
    )


def main():
    """Fonction principale de démonstration."""

    print("=" * 70)
    print("ALERT TRIAGER - Démonstration")
    print("=" * 70)
    print()

    # Créer une alerte d'exemple
    alert = create_sample_alert()

    print(f"Alerte: {alert.alert_id}")
    print(f"Titre: {alert.title}")
    print(f"Source: {alert.source}")
    print(f"Règle: {alert.rule_id}")
    print()

    # Créer le triager avec le provider mock
    triager = AlertTriager(providers=[MockThreatIntelProvider()])

    # Effectuer le triage
    result = triager.triage(alert)

    # Afficher les résultats
    print("=" * 70)
    print("RÉSULTAT DU TRIAGE")
    print("=" * 70)
    print()

    print(f"{'Statut:':<25} {result.status.value}")
    print(f"{'Sévérité:':<25} {result.severity.name}")
    print(f"{'Faux positif:':<25} {'Oui' if result.is_false_positive else 'Non'}")
    if result.false_positive_reason:
        print(f"{'Raison FP:':<25} {result.false_positive_reason}")
    print(f"{'Escalade:':<25} {'Oui' if result.escalate else 'Non'}")
    print()

    print("IOCs extraits:")
    for ioc in result.extracted_iocs:
        print(f"  - [{ioc.ioc_type.value}] {ioc.value}")
    print()

    print("Enrichissements:")
    for e in result.enrichments:
        status = "MALVEILLANT" if e.is_malicious else "OK"
        print(f"  - {e.ioc_value}: {status} ({e.source}, {e.confidence})")
    print()

    if result.escalate_to:
        print("Escalader vers:")
        for contact in result.escalate_to:
            print(f"  - {contact}")
        print()

    print(f"Action recommandée:\n  {result.recommended_action}")
    print()

    if result.mitre_techniques:
        print("Techniques MITRE ATT&CK:")
        for tech in result.mitre_techniques:
            print(f"  - {tech}")
        print()

    print("Notes d'analyse:")
    print(result.analyst_notes)
    print()

    # Export JSON
    print("=" * 70)
    print("EXPORT JSON")
    print("=" * 70)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
