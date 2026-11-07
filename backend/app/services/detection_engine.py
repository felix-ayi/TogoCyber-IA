"""Deterministic first-pass detection rules for normalized network events."""

import re

from backend.app.schemas.events import NormalizedEvent

_RULES = (
    ("brute force|password guessing|authentication", "Credential Access", "T1110", "Brute Force", 82),
    ("phishing|suspicious tls|malware|trojan|ransomware", "Initial Access", "T1566", "Phishing", 88),
    ("command and control|c2|beacon|callback", "Command and Control", "T1071", "Application Layer Protocol", 86),
    ("exploit|remote code|shellcode|vulnerability", "Initial Access", "T1190", "Exploit Public-Facing Application", 90),
    ("port scan|network scan|reconnaissance", "Discovery", "T1046", "Network Service Discovery", 68),
    ("data exfil|large transfer|exfiltration", "Exfiltration", "T1041", "Exfiltration Over C2 Channel", 92),
)


def assess_suricata_event(event: NormalizedEvent) -> dict:
    text = " ".join((event.message or "", event.event_type, event.metadata.get("category") or "")).lower()
    matched = None
    for pattern, tactic, technique, name, score in _RULES:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matched = (tactic, technique, name, score)
            break

    severity_score = {"CRITICAL": 95, "HIGH": 78, "MEDIUM": 58, "LOW": 35, "INFO": 20}
    source_score = severity_score[event.severity]
    risk_score = max(source_score, matched[3] if matched else 0)
    if risk_score >= 90:
        alert_severity = "CRITICAL"
    elif risk_score >= 70:
        alert_severity = "HIGH"
    else:
        alert_severity = "MEDIUM"

    should_alert = event.severity in {"CRITICAL", "HIGH", "MEDIUM"} or matched is not None
    tactic = matched[0] if matched else "Impact"
    technique = matched[1] if matched else "T1204"
    technique_name = matched[2] if matched else "User Execution"
    return {
        "should_alert": should_alert,
        "risk_score": int(risk_score),
        "severity": alert_severity,
        "mitre": {"tactic": tactic, "technique": technique, "name": technique_name},
        "recommendations": [
            "Vérifier le contexte de l’événement dans les journaux de l’hôte et du réseau.",
            "Corréler l’adresse source, la destination et le compte utilisateur avant toute action.",
            "Conserver une preuve horodatée et demander une validation humaine avant tout blocage.",
        ],
    }
