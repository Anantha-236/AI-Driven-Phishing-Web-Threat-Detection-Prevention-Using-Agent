"""
Pydantic Request & Response Models for CAPSTONE-1 Backend
Includes strict privacy validators ensuring untrusted input contains no raw user values or secrets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class PageModel(BaseModel):
    id: str
    url: str
    domain: str
    title: Optional[str] = ""
    formIds: Optional[List[str]] = Field(default_factory=list)
    scriptCount: Optional[int] = 0
    isHTTPS: bool = False


class FormModel(BaseModel):
    id: str
    action: Optional[str] = ""
    isCrossDomain: bool = False
    method: str = "GET"
    inputIds: Optional[List[str]] = Field(default_factory=list)
    hasPasswordField: bool = False
    hasOtpField: bool = False
    autocompleteAttributes: Optional[List[str]] = Field(default_factory=list)
    detectedDataTypes: Optional[List[str]] = Field(default_factory=list)
    target: Optional[str] = ""


class InputModel(BaseModel):
    id: str
    inputType: str
    name: Optional[str] = ""
    idAttribute: Optional[str] = ""
    autocomplete: Optional[str] = ""
    isPassword: bool = False
    isOtp: bool = False
    detectedDataTypes: Optional[List[str]] = Field(default_factory=list)
    isRequired: Optional[bool] = False

    @field_validator("name", "idAttribute", "autocomplete", mode="before")
    def sanitize_field(cls, v: Any) -> str:
        return str(v or "")


class ScriptModel(BaseModel):
    id: str
    src: Optional[str] = None
    isInline: bool = False
    isCrossDomain: bool = False


class RequestModel(BaseModel):
    id: str
    url: str
    method: str = "GET"
    isCrossDomain: bool = False


class ObservationRequest(BaseModel):
    schemaVersion: str = "3.0.0"
    collectionId: str
    timestamp: int
    page: PageModel
    forms: List[FormModel] = Field(default_factory=list)
    inputs: List[InputModel] = Field(default_factory=list)
    scripts: List[ScriptModel] = Field(default_factory=list)
    requests: List[RequestModel] = Field(default_factory=list)
    requestedDataTypes: Optional[List[str]] = Field(default_factory=list)
    threatLevel: Optional[str] = None
    modelScore: Optional[float] = None
    policyAction: Optional[str] = None

    @field_validator("forms", "inputs", mode="before")
    def reject_raw_secrets(cls, v: Any) -> Any:
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    # Strict privacy gate: reject if payload contains "value", "password_value", etc.
                    for forbidden in ["value", "password_value", "raw_value", "secret", "cvv_value", "otp_value"]:
                        if forbidden in item:
                            raise ValueError(f"Privacy violation: payload contains forbidden secret field '{forbidden}'")
        return v


class ObservationResponse(BaseModel):
    status: str = "ACCEPTED"
    observationId: str
    collectionId: str
    domain: str
    requestedDataTypes: List[str]
    isStored: bool


class ServiceDomainModel(BaseModel):
    domain: str
    is_primary: bool = False


class ServiceProfileResponse(BaseModel):
    service_id: str
    service_name: str
    category: str
    declared_behavior: Optional[Dict[str, Any]] = None
    domains: List[ServiceDomainModel] = Field(default_factory=list)


class ModelInfoResponse(BaseModel):
    model_id: str
    version: str
    model_type: str
    sha256_hash: str
    is_active: bool
