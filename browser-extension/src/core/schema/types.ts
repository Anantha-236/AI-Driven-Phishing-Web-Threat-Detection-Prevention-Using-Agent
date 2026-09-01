import { SCHEMA_V3_VERSION } from "./version";

// --- Data Type Categories for Privacy-Safe Field Classification ---
export type DataTypeCategory =
  | "EMAIL"
  | "USERNAME"
  | "PASSWORD"
  | "OTP"
  | "PHONE"
  | "ADDRESS"
  | "DATE_OF_BIRTH"
  | "IDENTITY_DOCUMENT"
  | "PAYMENT_CARD"
  | "CARD_EXPIRY"
  | "CVV"
  | "BANK_ACCOUNT"
  | "FILE_UPLOAD"
  | "CAMERA"
  | "MICROPHONE"
  | "LOCATION";

// --- Runtime Types ---
export type RuntimeEnvironment = "service-worker" | "offscreen" | "content-script";

export interface ExtensionContext {
  extensionVersion: string;
  schemaVersion: typeof SCHEMA_V3_VERSION;
  runtime: RuntimeEnvironment;
  timestamp: number;
}

export type RuntimeMessageType =
  | "PING"
  | "EVIDENCE_COLLECTED"
  | "MODEL_RESULT"
  | "POLICY_DECISION"
  | "GET_LATEST_DECISION";

export interface ExtensionMessage<T = unknown> {
  type: RuntimeMessageType;
  source: RuntimeEnvironment;
  target: RuntimeEnvironment;
  payload: T;
  timestamp: number;
}

// --- Artifact Types ---
export interface BaseArtifact {
  id: string;
  type: string;
  timestamp: number;
}

export interface PageArtifact extends BaseArtifact {
  type: "page";
  url: string;
  domain: string;
  title: string;
  formIds: string[];
  scriptCount: number;
  isHTTPS: boolean;
}

export interface FormArtifact extends BaseArtifact {
  type: "form";
  pageId: string;
  action: string;
  isCrossDomain: boolean;
  method: string;
  inputIds: string[];
  hasPasswordField: boolean;
  hasOtpField: boolean;
  autocompleteAttributes: string[];
  detectedDataTypes?: DataTypeCategory[];
  target?: string;
}

export interface InputArtifact extends BaseArtifact {
  type: "input";
  formId?: string;
  pageId: string;
  inputType: string;
  name: string;
  idAttribute: string;
  autocomplete: string;
  isPassword: boolean;
  isOtp: boolean;
  detectedDataTypes?: DataTypeCategory[];
  isRequired?: boolean;
  // NOTE: Value, innerText, and textContent are EXPLICITLY and STRICTLY excluded for privacy
}

export interface ScriptArtifact extends BaseArtifact {
  type: "script";
  pageId: string;
  src?: string;
  isInline: boolean;
  isCrossDomain: boolean;
}

export interface RequestArtifact extends BaseArtifact {
  type: "request";
  pageId: string;
  url: string;
  method: string;
  isCrossDomain: boolean;
}

export interface NavigationArtifact extends BaseArtifact {
  type: "navigation";
  targetUrl: string;
  referrer: string;
  pageId: string;
}

export type Artifact =
  | PageArtifact
  | FormArtifact
  | InputArtifact
  | ScriptArtifact
  | RequestArtifact
  | NavigationArtifact;

// --- Evidence Types ---
export interface EvidenceRelationship {
  sourceId: string;
  targetId: string;
  relation: "contains" | "navigates_to" | "triggers" | "requests";
}

export interface EvidenceCollection {
  schemaVersion: typeof SCHEMA_V3_VERSION;
  collectionId: string;
  timestamp: number;
  page: PageArtifact;
  forms: FormArtifact[];
  inputs: InputArtifact[];
  scripts: ScriptArtifact[];
  requests: RequestArtifact[];
  relationships: EvidenceRelationship[];
  requestedDataTypes?: DataTypeCategory[];
}

// --- Feature Types ---
export interface FeatureVector {
  has_password_field: boolean;
  has_otp_field: boolean;
  cross_domain_form: boolean;
  form_count: number;
  input_count: number;
  has_email_field?: boolean;
  has_username_field?: boolean;
  has_phone_field?: boolean;
  has_card_field?: boolean;
  has_cvv_field?: boolean;
  has_identity_field?: boolean;
  has_bank_field?: boolean;
  has_file_upload?: boolean;
  [key: string]: boolean | number | string | undefined;
}

// --- Model / Inference Types ---
export interface ModelResult {
  rawScore: number;            // 0.00 to 1.00
  inferenceLatencyMs: number;
  runtimeUsed: "service-worker" | "offscreen";
  modelId: string;
}

export type ThreatLevel = "benign" | "suspicious" | "malicious" | "insufficient_evidence";

export interface ThreatAssessment {
  threatLevel: ThreatLevel;
  score: number;
  confidence: number;
  evaluatedAt: number;
  reasons: string[];
}

// --- Policy Types ---
export type PolicyAction = "ALLOW" | "WARN" | "CONFIRM" | "BLOCK" | "CONTAIN";

export type EnforcementOutcome =
  | "BLOCKED_BEFORE_LOAD"
  | "CONTAINED_AFTER_LOAD"
  | "WARNED"
  | "ALLOWED"
  | "ENFORCEMENT_FAILED";

export interface PolicyDecision {
  action: PolicyAction;
  outcome: EnforcementOutcome;
  reason: string;
  timestamp: number;
}

