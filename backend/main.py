"""
CAPSTONE-1 FastAPI Supporting Backend Service
Provides endpoints for health checks, model metadata, service registry, and observation telemetry ingestion.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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
            page_domain=observation.page.domain,
            page_url_sanitized=sanitized_url,
            is_https=observation.page.isHTTPS,
            form_count=len(observation.forms),
            input_count=len(observation.inputs),
            script_count=len(observation.scripts),
            requested_data_types=requested_types,
            threat_level=observation.threatLevel,
            model_score=observation.modelScore,
            policy_action=observation.policyAction,
        )

        return ObservationResponse(
            status="ACCEPTED",
            observationId=obs_id,
            collectionId=observation.collectionId,
            domain=observation.page.domain,
            requestedDataTypes=requested_types,
            isStored=stored,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Observation processing error: {str(e)}",
        )
