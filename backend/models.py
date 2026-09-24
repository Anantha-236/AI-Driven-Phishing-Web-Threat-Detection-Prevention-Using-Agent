"""
Pydantic Request & Response Models for CAPSTONE-1 Backend
Includes strict privacy validators ensuring untrusted input contains no raw user values or secrets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Literal
from urllib.parse import urlsplit
from pydantic import BaseModel as PydanticBaseModel, ConfigDict, Field, field_validator, model_validator
from backend.events import SensitiveType, origin_only


class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PageModel(BaseModel):
    id: str
    url: str = Field(min_length=1, max_length=1024)
    domain: str = Field(min_length=1, max_length=255)
    title: Literal[""] = ""
    formIds: Optional[List[str]] = Field(default_factory=list)
    scriptCount: Optional[int] = 0
    isHTTPS: bool = False
    privacyPolicyUrl: Optional[str] = ""
    termsUrl: Optional[str] = ""

    _origins = field_validator("url", "privacyPolicyUrl", "termsUrl")(origin_only)

    @model_validator(mode="after")
    def domain_matches_origin(self):
        host = urlsplit(self.url).hostname
        # URL.hostname includes brackets for IPv6 in the browser collector.
        expected = f"[{host}]" if ":" in host else host
        if self.domain != expected:
            raise ValueError("domain must match page origin")
        return self


class FormModel(BaseModel):
    id: str
    action: Optional[str] = ""
    isCrossDomain: bool = False
    method: Literal["GET", "POST"] = "GET"
    inputIds: Optional[List[str]] = Field(default_factory=list)
    hasPasswordField: bool = False
    hasOtpField: bool = False
    autocompleteAttributes: List[str] = Field(default_factory=list, max_length=0)
    detectedDataTypes: Optional[List[SensitiveType]] = Field(default_factory=list)
    target: Literal[""] = ""

    _origin = field_validator("action")(origin_only)


class InputModel(BaseModel):
    id: str
    inputType: Literal["password", "email", "tel", "text", "number", "file", "checkbox", "radio", "submit", "select", "textarea"]
    name: Literal[""] = ""
    idAttribute: Literal[""] = ""
    autocomplete: Literal[""] = ""
    isPassword: bool = False
    isOtp: bool = False
    detectedDataTypes: Optional[List[SensitiveType]] = Field(default_factory=list)
    isRequired: Optional[bool] = False

class ScriptModel(BaseModel):
    id: str
    src: Optional[str] = None
    isInline: bool = False
    isCrossDomain: bool = False


    _origin = field_validator("src")(origin_only)


class RequestModel(BaseModel):
    id: str
    url: str
    method: Literal["GET", "POST"] = "GET"
    isCrossDomain: bool = False


    _origin = field_validator("url")(origin_only)


class ObservationRequest(BaseModel):
    schemaVersion: Literal["3.0.0"] = "3.0.0"
    # Collector IDs are coll-<base36 timestamp>-<numeric counter>.
    collectionId: str = Field(pattern=r"^coll-[a-z0-9]{1,13}-[0-9]{1,16}$", max_length=64)
    timestamp: int = Field(ge=0)
    deviceId: str = Field(default="", pattern=r"^(?:|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$")
    devicePlatform: Literal[""] = ""
    page: PageModel
    forms: List[FormModel] = Field(default_factory=list)
    inputs: List[InputModel] = Field(default_factory=list)
    scripts: List[ScriptModel] = Field(default_factory=list)
    requests: List[RequestModel] = Field(default_factory=list)
    requestedDataTypes: Optional[List[SensitiveType]] = Field(default_factory=list)
    threatLevel: Literal["benign", "suspicious", "malicious", "insufficient_evidence"] | None = None
    modelScore: Optional[float] = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    policyAction: Literal["ALLOW", "WARN", "CONFIRM", "BLOCK", "CONTAIN"] | None = None

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


class ObservationResponse(PydanticBaseModel):
    status: str = "ACCEPTED"
    observationId: str
    collectionId: str
    domain: str
    requestedDataTypes: List[str]
    isStored: bool


class ServiceDomainModel(PydanticBaseModel):
    domain: str
    is_primary: bool = False


class ServiceProfileResponse(PydanticBaseModel):
    service_id: str
    service_name: str
    category: str
    declared_behavior: Optional[Dict[str, Any]] = None
    domains: List[ServiceDomainModel] = Field(default_factory=list)


class ModelInfoResponse(PydanticBaseModel):
    model_id: str
    version: str
    model_type: str
    sha256_hash: str
    is_active: bool
