"""
CAPSTONE-1 FastAPI Supporting Backend Service
Provides endpoints for health checks, model metadata, service registry, and observation telemetry ingestion.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from backend.events import EventBatch, SecurityReport, AgentRequest, run_ml_agent

from backend.database import db_instance
from backend.models import (
    ModelInfoResponse,
    ObservationRequest,
    ObservationResponse,
    ServiceProfileResponse,
)

app = FastAPI(
    title="CAPSTONE-1 Backend API",
    version="1.1.0",
    description="Supporting API for CAPSTONE-1 Threat Detection Engine",
)

# CORS Middleware for extension or trusted dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    """System health check endpoint."""
    db_ok = db_instance.is_healthy()
    return {
        "status": "HEALTHY" if db_ok else "DEGRADED",
        "service": "CAPSTONE-1 Backend",
        "version": "1.1.0",
        "database": "CONNECTED" if db_ok else "DISCONNECTED",
        "timestamp": int(time.time()),
    }


@app.get("/api/v1/models/current", response_model=ModelInfoResponse)
async def get_current_model():
    """Retrieve active ML model metadata and checksum."""
    model = db_instance.get_active_model()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active model found in registry",
        )
    return model


@app.get("/api/v1/services/{service_id}", response_model=ServiceProfileResponse)
async def get_service_profile(service_id: str):
    """Retrieve service identity profile and registered legitimate domains."""
    profile = db_instance.get_service_profile(service_id.lower())
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service profile '{service_id}' not found in registry",
        )
    return profile


@app.get("/api/v1/observations")
async def get_recent_observations(limit: int = Query(default=20, ge=1, le=100)) -> Dict[str, Any]:
    """Return recent privacy-safe observations from PostgreSQL for debugging and monitoring."""
    rows = db_instance.list_observations(limit=limit)
    return {
        "count": len(rows),
        "limit": limit,
        "items": rows,
    }


@app.post("/api/v1/observations", response_model=ObservationResponse, status_code=status.HTTP_201_CREATED)
async def ingest_observation(observation: ObservationRequest):
    """
    Ingest privacy-preserving observation telemetry from browser content script.
    Validates schema and stores sanitized metadata without collecting raw secrets.
    """
    try:
        # Sanitize URL to strip sensitive query strings if present
        parsed = urlparse(observation.page.url)
        sanitized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else observation.page.url

        obs_id = f"obs-{uuid.uuid4().hex[:12]}"
        requested_types = observation.requestedDataTypes or []

        # Derive requested categories if not explicitly populated
        if not requested_types:
            derived = set()
            for inp in observation.inputs:
                if inp.detectedDataTypes:
                    for dt in inp.detectedDataTypes:
                        derived.add(dt)
                elif inp.isPassword:
                    derived.add("PASSWORD")
                elif inp.isOtp:
                    derived.add("OTP")
            requested_types = list(derived)

        stored = db_instance.store_observation(
            observation_id=obs_id,
            collection_id=observation.collectionId,
            device_id=observation.deviceId or "device-unknown",
            device_platform=observation.devicePlatform or "",
            page_domain=observation.page.domain,
            page_url_sanitized=sanitized_url,
            is_https=observation.page.isHTTPS,
            form_count=len(observation.forms),
            input_count=len(observation.inputs),
            script_count=len(observation.scripts),
            requested_data_types=requested_types,
            privacy_policy_url=observation.page.privacyPolicyUrl or "",
            terms_url=observation.page.termsUrl or "",
            threat_level=observation.threatLevel,
            model_score=observation.modelScore,
            policy_action=observation.policyAction,
        )

        if not stored:
            raise HTTPException(status_code=503, detail="Observation storage unavailable")

        return ObservationResponse(
            status="ACCEPTED",
            observationId=obs_id,
            collectionId=observation.collectionId,
            domain=observation.page.domain,
            requestedDataTypes=requested_types,
            isStored=stored,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Observation processing error")


@app.exception_handler(RequestValidationError)
async def validation_error(_request, _exc):
    # Pydantic default errors echo rejected input, including a potential secret.
    return JSONResponse(status_code=422, content={"detail": "Invalid sanitized payload"})


@app.post("/api/v1/events/batch", status_code=201)
def ingest_events(batch: EventBatch):
    try:
        with db_instance.get_connection() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO events_sanitized (session_id, tab_id, event_seq, document_id, event_type, event) "
                    "VALUES (%s, %s, %s, %s, %s, %s::jsonb) "
                    "ON CONFLICT (session_id, tab_id, event_seq) DO NOTHING",
                    [(e.session_id, e.tab_id, e.event_seq, e.document_id, e.event_type, json.dumps(e.model_dump())) for e in batch.events],
                )
                for event in batch.events:
                    cur.execute('SELECT event FROM events_sanitized WHERE session_id=%s AND tab_id=%s AND event_seq=%s',
                                (event.session_id, event.tab_id, event.event_seq))
                    if cur.fetchone()[0] != event.model_dump():
                        raise HTTPException(status_code=409, detail='Event identity conflict')
            conn.commit()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Event storage unavailable")
    return {"accepted": len(batch.events), "isStored": True}


@app.post('/api/v1/assessments', status_code=201)
def ingest_assessment(report: SecurityReport):
    try:
        with db_instance.get_connection() as conn:
            conn.execute('INSERT INTO assessments_sanitized (session_id, tab_id, event_seq, document_id, report) '
                         'VALUES (%s, %s, %s, %s, %s::jsonb) ON CONFLICT (session_id, tab_id, event_seq) '
                         'DO UPDATE SET report = EXCLUDED.report',
                         (report.session_id, report.tab_id, report.event_seq, report.document_id, json.dumps(report.model_dump())))
            conn.commit()
    except Exception:
        raise HTTPException(status_code=503, detail='Assessment storage unavailable')
    return {'isStored': True, 'event_seq': report.event_seq}


@app.post('/api/v1/agent/assess', deprecated=True, summary='Historical controlled-model research replay; browser decisions are local')
def assess_with_agent(request: AgentRequest):
    try:
        report = run_ml_agent(request)
    except (ValueError, OSError, KeyError, TypeError):
        raise HTTPException(status_code=503, detail='Agent model or observation unavailable')
    try:
        ingest_assessment(report)
        stored = True
    except HTTPException:
        stored = False
    return {'report': report.model_dump(), 'isStored': stored}
