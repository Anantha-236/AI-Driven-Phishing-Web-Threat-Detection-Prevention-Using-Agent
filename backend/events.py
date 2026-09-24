"""M1 typed event contract, integrated into CAPSTONE's existing FastAPI/DB.

Adapted from TSFEG-M1-FOUNDATION/backend/app/models.py. No second server/pool.
"""
from typing import Literal
from urllib.parse import urlsplit
import ipaddress
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SensitiveType = Literal['PASSWORD', 'OTP', 'CARD', 'CVV', 'EMAIL', 'PHONE', 'USERNAME', 'ID', 'RECOVERY', 'OTHER_SENSITIVE', 'NON_SENSITIVE', 'UNKNOWN']
PagePurpose = Literal['LOGIN', 'SIGNUP', 'PAYMENT', 'RECOVERY', 'IDENTITY_VERIFICATION', 'INFORMATIONAL', 'DOWNLOAD', 'UNKNOWN']

def origin_only(value: str | None) -> str | None:
    if value is None or value == '':
        return value
    p = urlsplit(value)
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('expected http(s) origin without userinfo')
    if p.path or p.query or p.fragment or any(c.isspace() for c in value) or '\\' in value:
        raise ValueError('expected origin only')
    port = p.port  # Reject malformed/out-of-range ports.
    host = p.hostname.encode('idna').decode('ascii')
    if ':' in host:
        if '%' in host:
            raise ValueError('IPv6 zone identifiers are not browser origins')
        host = '[' + ipaddress.IPv6Address(host).compressed + ']'
    elif any(not (c.isalnum() or c in '.-') for c in host):
        raise ValueError('invalid host')
    else:
        # WHATWG numeric-ending hosts are IPv4, not ordinary domain names.
        last = host.removesuffix('.').rsplit('.', 1)[-1]
        if last.isdecimal() or (last.startswith('0x') and all(c in '0123456789abcdef' for c in last[2:])):
            host = str(ipaddress.IPv4Address(host))
    canonical = f'{p.scheme}://{host}'
    if port is not None and port != (443 if p.scheme == 'https' else 80):
        canonical += f':{port}'
    if value != canonical:
        raise ValueError('origin must be canonical')
    return canonical

class SanitizedEvent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema_version: Literal['1.1.0', '1.2.0']
    evidence_status: Literal['OBSERVED'] = 'OBSERVED'
    analysis_version: Literal['event-analysis-1'] = 'event-analysis-1'
    model_version: Literal['pending'] = 'pending'
    policy_version: Literal['evidence-policy-1'] = 'evidence-policy-1'
    session_id: str = Field(pattern=r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
    tab_id: int = Field(ge=0)
    document_id: str | None = Field(default=None, pattern=r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$')
    frame_id: int = Field(ge=0)
    parent_frame_id: int | None = Field(default=None, ge=-1)
    event_seq: int = Field(ge=1)
    event_type: Literal['DOCUMENT_STARTED', 'FIELD_DISCOVERED', 'SENSITIVE_INTERACTION', 'DOM_MUTATION', 'FORM_TARGET_OBSERVED', 'REQUEST_OBSERVED', 'NAVIGATION_COMMITTED', 'REDIRECT_OBSERVED', 'HISTORY_UPDATED', 'DOCUMENT_ENDED', 'FORM_DISCOVERED', 'FORM_TARGET_CHANGED', 'FORM_SUBMISSION_ATTEMPT', 'SUBMISSION_PREVENTED', 'SUBMISSION_CONFIRMED', 'NAVIGATION_STARTED', 'FRAME_CREATED', 'FRAME_NAVIGATED', 'PAGE_CONTEXT_OBSERVED']
    page_purpose: PagePurpose | None = None
    purpose_source: Literal['STATIC_SEMANTICS', 'UNKNOWN'] | None = None
    sensitive_type: SensitiveType | None = None
    field_id: str | None = Field(default=None, pattern=r'^e-\d{1,8}$')
    form_id: str | None = Field(default=None, pattern=r'^f-\d{1,8}$')
    frame_origin: str | None = None
    target_origin: str | None = None
    destination_origin: str | None = None
    initiator_origin: str | None = None
    request_type: Literal['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'] | None = None
    interaction_type: Literal['focus', 'input', 'submit'] | None = None
    trust: Literal['ISOLATED_CONTENT_SCRIPT', 'WEBREQUEST_METADATA', 'WEBNAVIGATION_METADATA']
    timestamp_ms: int = Field(ge=0)
    received_ms: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1)

    @model_validator(mode='after')
    def purpose_category_only(self):
        if self.event_type == 'PAGE_CONTEXT_OBSERVED':
            if self.page_purpose is None or self.purpose_source is None:
                raise ValueError('Missing page-purpose category')
            if (self.page_purpose == 'UNKNOWN') != (self.purpose_source == 'UNKNOWN'):
                raise ValueError('Inconsistent page-purpose provenance')
        elif self.page_purpose is not None or self.purpose_source is not None:
            raise ValueError('Purpose only allowed on context observation')
        return self

    @field_validator('frame_origin', 'target_origin', 'destination_origin', 'initiator_origin')
    @classmethod
    def origins(cls, value):
        if value == '':
            raise ValueError('use null for unknown origin')
        return origin_only(value)

class EventBatch(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    events: list[SanitizedEvent] = Field(min_length=1, max_length=100)

class RelationshipEvidence(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    code: Literal['sensitive_cross_target', 'target_changed_after_interaction', 'request_near_interaction', 'cross_request_near_interaction', 'password_then_otp', 'dynamic_sensitive_field', 'submission_target_mismatch', 'frame_origin_mismatch']
    evidence_status: Literal['OBSERVED', 'INFERRED']
    event_seqs: list[int] = Field(min_length=1, max_length=3)

class OriginIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    status: Literal['KNOWN_LOGIN_ORIGIN', 'POSSIBLE_IMPERSONATION', 'UNKNOWN']
    service: Literal['google', 'paypal', 'microsoft'] | None

class FormDestination(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    document_id: str | None = Field(pattern=r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$')
    frame_id: int = Field(ge=0)
    form_id: str = Field(pattern=r'^f-\d{1,8}$')
    page_origin: str | None
    target_origin: str | None
    status: Literal['UNKNOWN', 'SAME_ORIGIN', 'HTTPS_DOWNGRADE', 'KNOWN_LOGIN_ORIGIN', 'UNVERIFIED_CROSS_ORIGIN']
    sensitive_types: list[SensitiveType] = Field(max_length=12)
    event_seq: int = Field(ge=1)
    _origins = field_validator('page_origin', 'target_origin')(origin_only)

ContextPositive = Literal['SENSITIVE_TARGET_SAME_ORIGIN', 'REPEATED_STABLE_SENSITIVE_TARGET', 'REQUEST_MATCHES_APPARENT_PURPOSE', 'AUTHENTICATION_SEQUENCE_CONSISTENT']
ContextContradiction = Literal['SENSITIVE_HTTPS_DOWNGRADE', 'SENSITIVE_TARGET_CHANGED_AFTER_INTERACTION', 'SENSITIVE_SUBMISSION_TARGET_CHANGED', 'INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED', 'SENSITIVE_REQUEST_PURPOSE_MISMATCH', 'POSSIBLE_IDENTITY_ORIGIN_MISMATCH']
CoverageCode = Literal['DOCUMENT_START', 'FIELD_SCAN', 'DOCUMENT_CORRELATION', 'APPARENT_PURPOSE', 'SENSITIVE_DESTINATIONS', 'COLLECTION_LOSS']

class PurposeAssessment(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    value: PagePurpose
    evidence_status: Literal['INFERRED', 'UNKNOWN']
    confidence: Literal['LOW', 'MEDIUM']
    basis: list[Literal['STATIC_SEMANTIC_CATEGORY', 'STRUCTURAL_FIELD_TYPES']] = Field(max_length=2)
    limitations: list[Literal['PAGE_CLAIM_NOT_INDEPENDENTLY_VERIFIED', 'NO_INDEPENDENT_PURPOSE_OBSERVATION', 'FIELD_TYPES_DO_NOT_ESTABLISH_INTENT']] = Field(max_length=3)

class EvidenceCompleteness(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    level: Literal['LOW', 'PARTIAL', 'SUFFICIENT']
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    observed: list[CoverageCode] = Field(max_length=6)
    missing: list[CoverageCode] = Field(max_length=6)

class SecurityReport(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema_version: Literal['event-report-1']
    analysis_version: Literal['event-analysis-1']
    policy_version: Literal['evidence-policy-1']
    session_id: str = Field(pattern=r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
    tab_id: int = Field(ge=0)
    document_id: str | None = Field(pattern=r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$')
    event_seq: int = Field(ge=1)
    timestamp_ms: int = Field(ge=0)
    page_origin: str | None
    destinations: list[str] = Field(max_length=100)
    threatLevel: Literal['benign', 'suspicious', 'malicious', 'insufficient_evidence']
    risk: Literal['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN']
    confidence: Literal['LOW', 'MEDIUM']
    confidence_kind: Literal['uncalibrated_evidence_coverage']
    action: Literal['ALLOW', 'WARN', 'CONFIRM']
    outcome: Literal['DECISION_ONLY', 'WARNING_DISPLAYED', 'SUBMIT_EVENT_CANCELLED', 'USER_CONFIRMED']
    requestedDataTypes: list[SensitiveType] = Field(max_length=12)
    evidence: list[RelationshipEvidence] = Field(max_length=16000)
    model_id: Literal['controlled-event-lr-1', 'unavailable']
    model_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    model_score: float | None = Field(ge=0, le=1, allow_inf_nan=False)
    model_provenance: Literal['CONTROLLED', 'SYNTHETIC', 'REAL', 'ARCHIVED', 'MIXED', 'UNAVAILABLE']
    unknowns: list[Literal['VALUE_TRANSMISSION_UNKNOWN', 'SERVER_BEHAVIOR_NOT_OBSERVABLE', 'IDENTITY_UNKNOWN', 'MODEL_UNCALIBRATED', 'COLLECTION_INCOMPLETE', 'PROGRAMMATIC_SUBMISSION_NOT_COVERED']] = Field(max_length=6)
    flat_parameters: list[float] = Field(min_length=14, max_length=14)
    relationship_parameters: list[float] = Field(min_length=22, max_length=22)
    analysis_latency_ms: float = Field(ge=0, allow_inf_nan=False)
    identity: OriginIdentity = Field(default_factory=lambda: OriginIdentity(status='UNKNOWN', service=None))
    form_destinations: list[FormDestination] = Field(default_factory=list, max_length=200)
    decision_source: Literal['BACKEND_ML_AGENT', 'LOCAL_FALLBACK', 'LOCAL_ML_AGENT'] = 'LOCAL_FALLBACK'
    agent_version: Literal['backend-ml-agent-1', 'local-context-agent-1'] | None = None
    decision_reasons: list[ContextPositive | ContextContradiction | Literal['DESTINATION_CHANGED', 'POSSIBLE_IMPERSONATION', 'HTTPS_DOWNGRADE', 'ML_ESCALATED_CONFIRMATION', 'INSUFFICIENT_EVIDENCE', 'NO_ELEVATED_PATTERN', 'LOCAL_CONTEXT_ASSESSMENT', 'MODEL_SUPPORTS_CONCERN', 'MODEL_SUPPORTS_LOW_RISK', 'MODEL_DISAGREES_WITH_CONTEXT', 'MODEL_UNAVAILABLE', 'INSUFFICIENT_CONTEXT', 'COLLECTION_INCOMPLETE', 'MODEL_ADVISORY_ONLY']] = Field(default_factory=list, max_length=32)
    model_contributions: list[float] = Field(default_factory=list, max_length=27)
    context_feature_version: Literal['context-features-1'] | None = None
    contextual_parameters: list[float] = Field(default_factory=list, max_length=27)
    purpose: PurposeAssessment | None = None
    positive_evidence: list[ContextPositive] = Field(default_factory=list, max_length=4)
    contradictions: list[ContextContradiction] = Field(default_factory=list, max_length=6)
    evidence_completeness: EvidenceCompleteness | None = None
    model_calibrated: bool = False
    agent_roundtrip_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    _origin = field_validator('page_origin')(origin_only)

    @model_validator(mode='after')
    def complete_context_contract(self):
        if self.decision_source == 'LOCAL_ML_AGENT':
            if self.context_feature_version != 'context-features-1' or len(self.contextual_parameters) != 27 or self.purpose is None or self.evidence_completeness is None or self.agent_version != 'local-context-agent-1':
                raise ValueError('Incomplete local context report')
        return self

    @field_validator('destinations')
    @classmethod
    def safe_destinations(cls, values):
        return [origin_only(v) for v in values]

    @field_validator('flat_parameters', 'relationship_parameters')
    @classmethod
    def finite_counts(cls, values):
        import math
        if any(not math.isfinite(v) or v < 0 or v != int(v) for v in values):
            raise ValueError('Expected finite nonnegative counts')
        return values

    @field_validator('contextual_parameters')
    @classmethod
    def finite_context(cls, values):
        import math
        if any(not math.isfinite(v) or not 0 <= v <= 10 for v in values):
            raise ValueError('Expected bounded finite contextual features')
        return values

    @field_validator('model_contributions')
    @classmethod
    def finite_contributions(cls, values):
        import math
        if not all(math.isfinite(v) for v in values): raise ValueError('Nonfinite contribution')
        return values

class AgentRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    events: list[SanitizedEvent] = Field(min_length=1, max_length=2000)
    incomplete: bool = False

    @model_validator(mode='after')
    def one_stream(self):
        first = self.events[0]
        if any((e.session_id, e.tab_id) != (first.session_id, first.tab_id) for e in self.events):
            raise ValueError('Mixed event stream')
        if any(a.event_seq >= b.event_seq for a, b in zip(self.events, self.events[1:])):
            raise ValueError('Unordered or duplicate event sequence')
        documents = {e.document_id for e in self.events if e.frame_id == 0 and e.document_id}
        if len(documents) != 1:
            raise ValueError('Expected one current top document')
        return self


# Canonical backend feature extraction from sanitized events, not client scores.
# Feature order matches event-features-1 and is tested against browser exports.
FLAT_FEATURES = ['event_count', 'form_count', 'input_count', 'password_count', 'otp_count',
                 'interaction_count', 'mutation_count', 'request_count', 'same_origin_requests',
                 'cross_origin_requests', 'navigation_count', 'redirect_count', 'destination_count', 'unknown_document_count']
RELATIONSHIP_FEATURES = ['sensitive_cross_target', 'target_changed_after_interaction', 'request_near_interaction',
                         'cross_request_near_interaction', 'password_then_otp', 'dynamic_sensitive_field',
                         'submission_target_mismatch', 'frame_origin_mismatch']

def event_features(events):
    flat = dict.fromkeys(FLAT_FEATURES, 0)
    relations = dict.fromkeys(RELATIONSHIP_FEATURES, 0)
    fields, targets, interactions, scoped_interactions, passwords, mutations, top_origins, sensitive_fields = ({ } for _ in range(8))
    forms, destinations, evidence = set(), set(), []
    def sensitive(event):
        return event.sensitive_type not in {None, 'UNKNOWN', 'NON_SENSITIVE'}
    def add(code, records, inferred=False):
        relations[code] += 1
        evidence.append(dict(code=code, evidence_status='INFERRED' if inferred else 'OBSERVED',
                             event_seqs=list(dict.fromkeys(e.event_seq for e in records))))
    for e in events:
        flat['event_count'] += 1
        if not e.document_id: flat['unknown_document_count'] += 1
        scope = (e.session_id, e.tab_id, e.document_id or f'unknown-{e.event_seq}', e.frame_id)
        tab = (e.session_id, e.tab_id)
        form = (*scope, e.form_id) if e.form_id else None
        if form: forms.add(form)
        destinations.update(o for o in [e.target_origin, e.destination_origin] if o)
        if e.frame_id == 0 and e.frame_origin: top_origins[tab] = e.frame_origin
        if e.event_type == 'FIELD_DISCOVERED':
            if e.field_id: fields[(*scope, e.field_id)] = e.sensitive_type
            if form and sensitive(e): sensitive_fields[form] = e
            if sensitive(e) and scope in mutations: add('dynamic_sensitive_field', [mutations[scope], e])
            if sensitive(e) and e.frame_id != 0 and e.frame_origin and tab in top_origins and e.frame_origin != top_origins[tab]: add('frame_origin_mismatch', [e])
        if e.event_type == 'DOM_MUTATION':
            flat['mutation_count'] += 1; mutations[scope] = e
        if e.event_type == 'SENSITIVE_INTERACTION':
            flat['interaction_count'] += 1; scoped_interactions[scope] = e
            if form: interactions[form] = e
            if e.sensitive_type == 'OTP' and scope in passwords: add('password_then_otp', [passwords[scope], e])
            if e.sensitive_type == 'PASSWORD': passwords[scope] = e
        if form and e.event_type in {'FORM_TARGET_OBSERVED', 'FORM_SUBMISSION_ATTEMPT'}:
            prior, interacted = targets.get(form), interactions.get(form)
            if prior and prior.target_origin and e.target_origin and prior.target_origin != e.target_origin:
                if interacted and interacted.event_seq > prior.event_seq and e.timestamp_ms >= interacted.timestamp_ms: add('target_changed_after_interaction', [prior, interacted, e])
                if e.event_type == 'FORM_SUBMISSION_ATTEMPT': add('submission_target_mismatch', [prior, e])
            targets[form] = e
        if e.event_type == 'REQUEST_OBSERVED':
            flat['request_count'] += 1
            if e.initiator_origin and e.destination_origin:
                flat['same_origin_requests' if e.initiator_origin == e.destination_origin else 'cross_origin_requests'] += 1
            near = scoped_interactions.get(scope)
            if near and 0 <= e.timestamp_ms - near.timestamp_ms <= 2500:
                add('request_near_interaction', [near, e], True)
                if e.initiator_origin and e.destination_origin and e.initiator_origin != e.destination_origin: add('cross_request_near_interaction', [near, e], True)
        if e.event_type == 'NAVIGATION_COMMITTED': flat['navigation_count'] += 1
        if e.event_type == 'REDIRECT_OBSERVED': flat['redirect_count'] += 1
    for form, field in sensitive_fields.items():
        target = targets.get(form)
        if target and target.target_origin and target.frame_origin and target.target_origin != target.frame_origin: add('sensitive_cross_target', [field, target])
    flat.update(form_count=len(forms), input_count=len(fields), destination_count=len(destinations),
                password_count=list(fields.values()).count('PASSWORD'), otp_count=list(fields.values()).count('OTP'))
    return [flat[k] for k in FLAT_FEATURES], relations, evidence


def agent_identity(origin):
    known = {'https://accounts.google.com': 'google', 'https://www.paypal.com': 'paypal', 'https://login.microsoftonline.com': 'microsoft'}
    if origin in known: return dict(status='KNOWN_LOGIN_ORIGIN', service=known[origin])
    host = urlsplit(origin or '').hostname or ''
    for service in ['google', 'paypal', 'microsoft']:
        parents = ['microsoft.com', 'microsoftonline.com'] if service == 'microsoft' else [service + '.com']
        if any(host == p or host.endswith('.' + p) for p in parents): break
        if service in host: return dict(status='POSSIBLE_IMPERSONATION', service=service)
    return dict(status='UNKNOWN', service=None)


def run_ml_agent(request: AgentRequest):
    import json, hashlib, math, time
    from pathlib import Path
    start = time.perf_counter()
    events = request.events
    flat, relations, evidence = event_features(events)
    relationship = flat + [relations[k] for k in RELATIONSHIP_FEATURES]
    raw = (Path(__file__).resolve().parents[1] / 'browser-extension/assets/event-model.json').read_bytes()
    model = json.loads(raw)
    vector = flat if model['representation'] == 'flat' else relationship
    if model['model_id'] != 'controlled-event-lr-1' or model['feature_version'] != 'event-features-1' or model['representation'] not in {'flat', 'relationship'}:
        raise ValueError('Unsupported model')
    if any(len(model[k]) != len(vector) for k in ['mean', 'scale', 'coefficients']) or any(not math.isfinite(v) or v <= 0 for v in model['scale']):
        raise ValueError('Invalid model shape or scaling')
    contributions = [(v - mean) / scale * coefficient for v, mean, scale, coefficient in zip(vector, model['mean'], model['scale'], model['coefficients'])]
    logit = model['intercept'] + sum(contributions)
    if not math.isfinite(logit): raise ValueError('Invalid model output')
    score = 1 / (1 + math.exp(-logit)) if logit >= 0 else math.exp(logit) / (1 + math.exp(logit))
    top = next((e for e in reversed(events) if e.frame_id == 0 and e.frame_origin), None)
    if top is None: raise ValueError('No observable top origin')
    identity = agent_identity(top.frame_origin)
    forms = {}
    for e in events:
        if not e.form_id or not e.document_id: continue
        key = (e.document_id, e.frame_id, e.form_id)
        form = forms.setdefault(key, dict(document_id=e.document_id, frame_id=e.frame_id, form_id=e.form_id,
            page_origin=e.frame_origin, target_origin=None, status='UNKNOWN', sensitive_types=[], event_seq=e.event_seq))
        if e.event_type == 'FIELD_DISCOVERED' and e.sensitive_type not in {None, 'UNKNOWN', 'NON_SENSITIVE'} and e.sensitive_type not in form['sensitive_types']: form['sensitive_types'].append(e.sensitive_type)
        if e.event_type in {'FORM_TARGET_OBSERVED', 'FORM_SUBMISSION_ATTEMPT'}:
            form.update(target_origin=e.target_origin, event_seq=e.event_seq)
            form['status'] = 'UNKNOWN' if not e.target_origin else 'HTTPS_DOWNGRADE' if (e.frame_origin or '').startswith('https:') and e.target_origin.startswith('http:') else 'SAME_ORIGIN' if e.target_origin == e.frame_origin else 'KNOWN_LOGIN_ORIGIN' if agent_identity(e.target_origin)['status'] == 'KNOWN_LOGIN_ORIGIN' else 'UNVERIFIED_CROSS_ORIGIN'
    reasons = []
    changed = relations['target_changed_after_interaction'] > 0 and relations['sensitive_cross_target'] > 0
    if changed: reasons.append('DESTINATION_CHANGED')
    if identity['status'] == 'POSSIBLE_IMPERSONATION' and any(f['sensitive_types'] for f in forms.values()): reasons.append('POSSIBLE_IMPERSONATION')
    if any(f['status'] == 'HTTPS_DOWNGRADE' and f['sensitive_types'] for f in forms.values()): reasons.append('HTTPS_DOWNGRADE')
    concerning = bool(reasons)
    corroborated = changed and any(relations[k] for k in ['password_then_otp', 'cross_request_near_interaction', 'submission_target_mismatch'])
    # Controlled ML may escalate corroborated suspicion to confirmation, never
    # approve a destination or authorize autonomous blocking from score alone.
    escalated = concerning and score >= .8 and not request.incomplete
    if escalated: reasons.append('ML_ESCALATED_CONFIRMATION')
    if not reasons: reasons.append('INSUFFICIENT_EVIDENCE' if request.incomplete else 'NO_ELEVATED_PATTERN')
    last = events[-1]
    outcome_event = next((e for e in reversed(events) if e.event_type in {'SUBMISSION_PREVENTED', 'SUBMISSION_CONFIRMED'}), None)
    unknowns = ['VALUE_TRANSMISSION_UNKNOWN', 'SERVER_BEHAVIOR_NOT_OBSERVABLE', 'IDENTITY_UNKNOWN', 'MODEL_UNCALIBRATED', 'PROGRAMMATIC_SUBMISSION_NOT_COVERED']
    if request.incomplete: unknowns.append('COLLECTION_INCOMPLETE')
    return SecurityReport(schema_version='event-report-1', analysis_version='event-analysis-1', policy_version='evidence-policy-1',
        session_id=last.session_id, tab_id=last.tab_id, document_id=top.document_id, event_seq=last.event_seq, timestamp_ms=int(time.time()*1000),
        page_origin=top.frame_origin, destinations=list(dict.fromkeys(o for e in events for o in [e.target_origin,e.destination_origin] if o))[:100],
        threatLevel='suspicious' if concerning else 'insufficient_evidence', risk='HIGH' if corroborated or escalated else 'MEDIUM' if concerning else 'UNKNOWN' if request.incomplete else 'LOW',
        confidence='LOW' if request.incomplete else 'MEDIUM', confidence_kind='uncalibrated_evidence_coverage',
        action='CONFIRM' if corroborated or escalated else 'WARN' if concerning else 'ALLOW',
        outcome='SUBMIT_EVENT_CANCELLED' if outcome_event and outcome_event.event_type == 'SUBMISSION_PREVENTED' else 'USER_CONFIRMED' if outcome_event else 'DECISION_ONLY',
        requestedDataTypes=list(dict.fromkeys(e.sensitive_type for e in events if e.event_type == 'FIELD_DISCOVERED' and e.sensitive_type not in {None,'UNKNOWN','NON_SENSITIVE'})),
        evidence=evidence, model_id=model['model_id'], model_sha256=hashlib.sha256(raw).hexdigest(), model_score=score, model_provenance='CONTROLLED',
        flat_parameters=flat, relationship_parameters=relationship, unknowns=unknowns, identity=identity, form_destinations=list(forms.values())[:200],
        decision_source='BACKEND_ML_AGENT', agent_version='backend-ml-agent-1', decision_reasons=reasons, model_contributions=contributions,
        analysis_latency_ms=(time.perf_counter()-start)*1000)
