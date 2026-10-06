"""CSV exports of SOC records for operator reporting.

Exports reuse the same role-scoped repository queries as the JSON API. Cells are sanitised
against spreadsheet formula injection (a leading =, +, -, @, tab or CR in a text value is
neutralised) so an exported file cannot execute when opened in Excel/LibreOffice.
"""

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from backend.app.core.auth import require_roles
from backend.app.repositories import (
    alert_repository,
    audit_repository,
    history_repository,
    ioc_repository,
)

router = APIRouter(prefix="/exports", tags=["Exports"])

_soc_roles = require_roles("Admin", "Analyst")
_admin_roles = require_roles("Admin")

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_COLUMNS = {
    "alerts": [
        "id", "history_id", "incident_id", "module", "title", "severity",
        "risk_score", "status", "assignee_user_id", "created_at", "updated_at",
    ],
    "incidents": [
        "id", "history_id", "owner_user_id", "module", "prediction", "risk_score",
        "severity", "status", "created_at", "updated_at",
    ],
    "iocs": [
        "id", "type", "value", "severity", "confidence", "source", "description",
        "status", "expires_at", "created_by", "created_at", "updated_at", "tags",
    ],
    "audit": [
        "id", "actor_user_id", "action", "outcome", "target_type", "target_id", "created_at",
    ],
}


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value)
    if isinstance(value, str):
        if value.startswith(_FORMULA_PREFIXES):
            return "'" + value
        return value
    return str(value)


def _to_csv(rows: list[dict], columns: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def _csv_response(content: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/alerts", dependencies=[Depends(_soc_roles)])
def export_alerts(
    limit: int = Query(default=100, ge=1, le=100),
    alert_status: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
):
    try:
        rows = alert_repository.list_alerts(limit=limit, status=alert_status, severity=severity)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _csv_response(_to_csv(rows, _COLUMNS["alerts"]), "togocyber-alerts.csv")


@router.get("/incidents", dependencies=[Depends(_soc_roles)])
def export_incidents(
    limit: int = Query(default=100, ge=1, le=100),
    incident_status: str | None = Query(default=None, alias="status"),
):
    try:
        rows = history_repository.list_incidents(limit=limit, status=incident_status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _csv_response(_to_csv(rows, _COLUMNS["incidents"]), "togocyber-incidents.csv")


@router.get("/iocs", dependencies=[Depends(_soc_roles)])
def export_iocs(
    limit: int = Query(default=100, ge=1, le=100),
    ioc_type: str | None = Query(default=None, alias="type"),
    ioc_status: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
):
    try:
        rows = ioc_repository.list_iocs(
            limit=limit, ioc_type=ioc_type, status=ioc_status, severity=severity
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _csv_response(_to_csv(rows, _COLUMNS["iocs"]), "togocyber-iocs.csv")


@router.get("/audit", dependencies=[Depends(_admin_roles)])
def export_audit(
    limit: int = Query(default=100, ge=1, le=100),
    action: str | None = Query(default=None),
):
    try:
        rows = audit_repository.list_events(limit=limit, action=action)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return _csv_response(_to_csv(rows, _COLUMNS["audit"]), "togocyber-audit.csv")
