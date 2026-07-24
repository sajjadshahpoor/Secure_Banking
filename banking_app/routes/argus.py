import logging
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, render_template, Request
from flask_login import login_required

from ..decorators import admin_required


argus_bp = Blueprint("argus", __name__)

argus_logger = logging.getLogger("argus")

# Keep only the most recent events to avoid unbounded memory growth.
MAX_EVENTS = 200
argus_events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)


def record_event(
    event_type: str,
    request: Request,
    threat_score: int,
    details: dict[str, Any] | None = None,
) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "ip_address": request.remote_addr or "Unknown",
        "endpoint": request.path,
        "method": request.method,
        "threat_score": threat_score,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "details": details or {},
    }

    argus_events.appendleft(event)

    print(
        f"[ARGUS] {event_type} | "
        f"IP={event['ip_address']} | "
        f"Endpoint={event['endpoint']} | "
        f"Threat={threat_score}"
    )

    argus_logger.warning(
        "ARGUS_EVENT event=%s ip=%s endpoint=%s "
        "method=%s threat_score=%s user_agent=%s details=%s",
        event_type,
        event["ip_address"],
        event["endpoint"],
        event["method"],
        threat_score,
        event["user_agent"],
        event["details"],
    )


def get_threat_level(score: float) -> str:
    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "CLEAR"


def get_threat_level_class(score: float) -> str:
    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


def build_dashboard_summary() -> dict[str, Any]:
    events = list(argus_events)

    total_events = len(events)

    high_severity_events = sum(
        1
        for event in events
        if event["threat_score"] >= 60
    )

    # Every stored ARGUS event represents a honeypot interaction.
    honeypot_triggers = total_events

    overall_risk_score = (
        round(
            sum(event["threat_score"] for event in events)
            / total_events
        )
        if total_events
        else 0
    )

    top_ip_counts = Counter(
        event["ip_address"]
        for event in events
    ).most_common(5)

    return {
        "total_events": total_events,
        "high_severity_events": high_severity_events,
        "honeypot_triggers": honeypot_triggers,
        "overall_risk_score": overall_risk_score,
        "overall_threat_level": get_threat_level(
            overall_risk_score
        ),
        "overall_threat_class": get_threat_level_class(
            overall_risk_score
        ),
        "top_ip_counts": top_ip_counts,
    }


@argus_bp.route("/argus/status")
def argus_status():
    return jsonify(
        {
            "engine": "ARGUS",
            "description": (
                "Banking Deception & Detection Engine"
            ),
            "status": "active",
        }
    )


# NOTE: /argus/events and /argus/dashboard show live details of every
# reconnaissance/exploitation attempt against the honeypot -- including
# source IPs and threat scores. If left public, the Red Team could simply
# visit these pages and watch themselves being tracked in real time, which
# defeats the point of a *hidden* detection layer. They're locked down the
# same way /soc is: authenticated Blue Team admins only.


@argus_bp.route("/argus/events")
@login_required
@admin_required
def argus_event_feed():
    return jsonify(
        {
            "engine": "ARGUS",
            "event_count": len(argus_events),
            "events": list(argus_events),
        }
    )


@argus_bp.route("/argus/dashboard")
@login_required
@admin_required
def argus_dashboard():
    return render_template(
        "argus_dashboard.html",
        events=list(argus_events),
        summary=build_dashboard_summary(),
    )
