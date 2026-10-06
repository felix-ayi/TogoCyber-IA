"""Integration adapter status.

Reports, for each external source, whether it is actually configured in this deployment.
Status is derived solely from the presence of the relevant environment configuration.
Nothing is simulated: an adapter that is not configured is reported as 'not_configured'
and no telemetry from it is ever invented.
"""

import os

# Each adapter maps to the environment variable(s) that must be present for it to be
# considered configured. We only report status; we never fabricate feed data.
_ADAPTERS = [
    {
        "key": "zeek",
        "name": "Zeek",
        "category": "network_sensor",
        "env": ["ZEEK_LOG_PATH"],
        "detail": "Journaux réseau Zeek (conn.log, dns.log…).",
    },
    {
        "key": "suricata",
        "name": "Suricata",
        "category": "ids",
        "env": ["SURICATA_EVE_PATH"],
        "detail": "Alertes IDS Suricata (eve.json).",
    },
    {
        "key": "syslog",
        "name": "Syslog",
        "category": "log_ingest",
        "env": ["SYSLOG_HOST", "SYSLOG_PORT"],
        "detail": "Collecte syslog entrante.",
    },
    {
        "key": "virustotal",
        "name": "VirusTotal",
        "category": "threat_intel",
        "env": ["VIRUSTOTAL_API_KEY"],
        "detail": "Enrichissement d’observables VirusTotal.",
    },
    {
        "key": "abuseipdb",
        "name": "AbuseIPDB",
        "category": "threat_intel",
        "env": ["ABUSEIPDB_API_KEY"],
        "detail": "Réputation d’adresses IP AbuseIPDB.",
    },
    {
        "key": "siem",
        "name": "SIEM",
        "category": "siem",
        "env": ["SIEM_API_URL", "SIEM_API_TOKEN"],
        "detail": "Export/ingestion vers un SIEM tiers.",
    },
    {
        "key": "smtp",
        "name": "SMTP (e-mail)",
        "category": "notification",
        "env": ["NOTIFICATION_SMTP_HOST"],
        "detail": "Canal de notification par e-mail.",
    },
    {
        "key": "slack",
        "name": "Slack",
        "category": "notification",
        "env": ["NOTIFICATION_SLACK_WEBHOOK"],
        "detail": "Canal de notification Slack.",
    },
    {
        "key": "webhook",
        "name": "Webhook générique",
        "category": "notification",
        "env": ["NOTIFICATION_WEBHOOK_URL"],
        "detail": "Canal de notification par webhook HTTP.",
    },
]

_NOT_CONFIGURED_DETAIL = (
    "Non configuré : aucune donnée de cette source n’est simulée. "
    "Renseignez la configuration requise pour l’activer."
)


def _is_configured(env_names: list[str]) -> bool:
    return all(bool(os.getenv(name, "").strip()) for name in env_names)


def integration_status() -> list[dict]:
    adapters = []
    for adapter in _ADAPTERS:
        configured = _is_configured(adapter["env"])
        adapters.append(
            {
                "key": adapter["key"],
                "name": adapter["name"],
                "category": adapter["category"],
                "status": "configured" if configured else "not_configured",
                "required_env": list(adapter["env"]),
                "detail": adapter["detail"] if configured else _NOT_CONFIGURED_DETAIL,
            }
        )
    return adapters


def status_summary() -> dict:
    adapters = integration_status()
    configured = sum(1 for item in adapters if item["status"] == "configured")
    return {
        "adapters": adapters,
        "configured": configured,
        "not_configured": len(adapters) - configured,
        "total": len(adapters),
    }
