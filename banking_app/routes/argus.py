import logging
from typing import Any

from flask import Blueprint, jsonify, Request


argus_bp = Blueprint("argus", __name__)

argus_logger = logging.getLogger("argus")


def record_event(
    event_type: str,
    request: Request,
    threat_score: int,
    details: dict[str, Any] | None = None,
) -> None:

    print(
        f"[ARGUS] {event_type} | "
        f"IP={request.remote_addr} | "
        f"Endpoint={request.path} | "
        f"Threat={threat_score}"
    )

    argus_logger.warning(
        "ARGUS_EVENT event=%s ip=%s endpoint=%s "
        "method=%s threat_score=%s user_agent=%s details=%s",
        event_type,
        request.remote_addr,
        request.path,
        request.method,
        threat_score,
        request.headers.get("User-Agent", "Unknown"),
        details or {},
    )


@argus_bp.route("/argus/status")
def argus_status():
    return jsonify(
        {
            "engine": "ARGUS",
            "description": "Banking Deception & Detection Engine",
            "status": "active",
        }
    )
