"""
CAPSTONE-1 Backend REST Service (Pure Python Standard Library)
Zero C-extension dependency - resilient against OS binary restrictions.
Provides endpoints for health checks, model metadata, service registry, and observation telemetry ingestion.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from backend.database import db_instance


def validate_privacy_safety(payload: Dict[str, Any]) -> None:
    """
    Strict privacy validation gate:
    Rejects any payload containing raw secrets, password values, tokens, or form values.
    """
    forbidden_keys = {
        "value",
        "password_value",
        "raw_value",
        "secret",
        "cvv_value",
        "otp_value",
        "pin_value",
        "card_value",
    }

    def _check(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in forbidden_keys:
                    raise ValueError(f"Privacy violation: payload contains forbidden secret field '{k}'")
                _check(v)
        elif isinstance(obj, list):
            for item in obj:
                _check(item)

    _check(payload)


def handle_request(method: str, path: str, body: Optional[bytes] = None) -> Tuple[int, Dict[str, Any]]:
    """
    Route and process API requests.
    Returns (status_code, response_dict).
    """
    parsed = urlparse(path)
    clean_path = parsed.path.rstrip("/")

    # 1. Health Check
    if method == "GET" and clean_path == "/api/v1/health":
        db_ok = db_instance.is_healthy()
        return HTTPStatus.OK, {
            "status": "HEALTHY" if db_ok else "DEGRADED",
            "service": "CAPSTONE-1 Backend",
            "version": "1.1.0",
            "database": "CONNECTED" if db_ok else "DISCONNECTED",
            "timestamp": int(time.time()),
        }

    # 2. Current Model Metadata
    if method == "GET" and clean_path == "/api/v1/models/current":
        model = db_instance.get_active_model()
        if not model:
            return HTTPStatus.NOT_FOUND, {"detail": "No active model found in registry"}
        return HTTPStatus.OK, {
            "model_id": model["model_id"],
            "version": model["version"],
            "model_type": model["model_type"],
            "sha256_hash": model["sha256_hash"],
            "is_active": bool(model["is_active"]),
        }

    # 3. Service Profile
    match_service = re.match(r"^/api/v1/services/([a-zA-Z0-9_\-]+)$", clean_path)
    if method == "GET" and match_service:
        service_id = match_service.group(1).lower()
        profile = db_instance.get_service_profile(service_id)
        if not profile:
            return HTTPStatus.NOT_FOUND, {"detail": f"Service profile '{service_id}' not found in registry"}
        return HTTPStatus.OK, profile

    # 4. Ingest Observations
    if method == "POST" and clean_path == "/api/v1/observations":
        if not body:
            return HTTPStatus.BAD_REQUEST, {"detail": "Missing JSON request body"}
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return HTTPStatus.BAD_REQUEST, {"detail": "Invalid JSON encoding"}

        # Validate privacy safety
        try:
            validate_privacy_safety(payload)
        except ValueError as err:
            return HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": str(err)}

        page_data = payload.get("page") or {}
        if not page_data.get("domain") or not page_data.get("url"):
            return HTTPStatus.BAD_REQUEST, {"detail": "Observation requires valid page domain and url"}

        # Sanitize URL: strip query parameters
        page_url = str(page_data.get("url", ""))
        url_p = urlparse(page_url)
        sanitized_url = f"{url_p.scheme}://{url_p.netloc}{url_p.path}" if url_p.netloc else page_url

        collection_id = str(payload.get("collectionId", f"coll-{uuid.uuid4().hex[:8]}"))
        obs_id = f"obs-{uuid.uuid4().hex[:12]}"

        requested_types = payload.get("requestedDataTypes") or []
        if not requested_types:
            derived = set()
            for inp in payload.get("inputs", []):
                if isinstance(inp, dict):
                    if inp.get("detectedDataTypes"):
                        for dt in inp["detectedDataTypes"]:
                            derived.add(dt)
                    elif inp.get("isPassword"):
                        derived.add("PASSWORD")
                    elif inp.get("isOtp"):
                        derived.add("OTP")
            requested_types = list(derived)

        forms = payload.get("forms") or []
        inputs = payload.get("inputs") or []
        scripts = payload.get("scripts") or []

        stored = db_instance.store_observation(
            observation_id=obs_id,
            collection_id=collection_id,
            page_domain=str(page_data.get("domain", "")),
            page_url_sanitized=sanitized_url,
            is_https=bool(page_data.get("isHTTPS", False)),
            form_count=len(forms),
            input_count=len(inputs),
            script_count=len(scripts),
            requested_data_types=requested_types,
            threat_level=payload.get("threatLevel"),
            model_score=payload.get("modelScore"),
            policy_action=payload.get("policyAction"),
        )

        return HTTPStatus.CREATED, {
            "status": "ACCEPTED",
            "observationId": obs_id,
            "collectionId": collection_id,
            "domain": str(page_data.get("domain", "")),
            "requestedDataTypes": requested_types,
            "isStored": stored,
        }

    return HTTPStatus.NOT_FOUND, {"detail": f"Route {method} {clean_path} not found"}


class CapstoneRequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        code, resp = handle_request("GET", self.path)
        self._send_json(code, resp)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None
        code, resp = handle_request("POST", self.path, body)
        self._send_json(code, resp)

    def _send_json(self, code: int, data: Dict[str, Any]):
        body_bytes = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logging during testing
        pass


def run_server(port: int = 8000, host: str = "127.0.0.1") -> HTTPServer:
    server = HTTPServer((host, port), CapstoneRequestHandler)
    print(f"[CAPSTONE-1 Backend] Listening on http://{host}:{port}/")
    return server


if __name__ == "__main__":
    server = run_server(8000)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
