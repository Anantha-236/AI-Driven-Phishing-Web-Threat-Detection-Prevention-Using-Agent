/**
 * CAPSTONE-1 Threat Assessment Module
 *
 * Converts ML model score + evidence context + declared service comparison into explainable threat assessments.
 *
 * Score mapping:
 *  - 0.0 to 0.3  → BENIGN (low risk)
 *  - 0.3 to 0.7  → SUSPICIOUS (medium risk, warrants user attention)
 *  - 0.7 to 1.0  → MALICIOUS (high risk, enforcement recommended)
 *
 * Assessment considers:
 *  - ML model score (primary signal)
 *  - Evidence structure & clarity
 *  - Declared service profile comparator
 *  - Explainable reason codes
 */

import {
  ModelResult,
  EvidenceCollection,
  FeatureVector,
  ThreatAssessment,
  ThreatLevel,
} from "./schema/types";
import { extractObservedEvents } from "./profiles/observed-behavior";
import { compareBehavior } from "./profiles/comparator";

export interface AssessmentContext {
  modelResult: ModelResult;
  evidence: EvidenceCollection;
  features: FeatureVector;
}

/**
 * Convert model score to threat level using calibrated thresholds.
 */
export function scoreToThreatLevel(score: number): ThreatLevel {
  if (typeof score !== "number" || isNaN(score) || score < 0) {
    return "insufficient_evidence";
  }
  if (score < 0.3) return "benign";
  if (score < 0.7) return "suspicious";
  return "malicious";
}

/**
 * Determine confidence score based on evidence quality and clarity.
 */
export function calculateConfidence(context: AssessmentContext): number {
  const { modelResult, features, evidence } = context;
  let confidence = 0.5; // baseline

  // Boost confidence for extreme scores
  if (modelResult.rawScore < 0.2 || modelResult.rawScore > 0.8) {
    confidence += 0.2;
  }

  // Boost confidence for multiple evidence signals
  const signalCount =
    (features.has_password_field ? 1 : 0) +
    (features.has_otp_field ? 1 : 0) +
    (features.cross_domain_form ? 1 : 0);

  confidence += signalCount * 0.1; // +0.1 per signal, max +0.3

  // Boost confidence for significant form/input counts
  if (features.form_count > 1) confidence += 0.1;
  if (features.input_count > 3) confidence += 0.1;

  // Reduce confidence if evidence is sparse
  if (
    evidence.forms.length === 0 &&
    evidence.scripts.length === 0 &&
    evidence.requests.length === 0
  ) {
    confidence -= 0.2;
  }

  return Math.max(0.1, Math.min(1.0, confidence));
}

/**
 * Generate human-readable reason codes explaining the assessment.
 */
export function generateReasons(context: AssessmentContext): string[] {
  const reasons: string[] = [];
  const { modelResult, features, evidence } = context;

  // Score-based reasons
  if (modelResult.rawScore > 0.8) {
    reasons.push("HIGH_ML_SCORE");
  } else if (modelResult.rawScore > 0.6) {
    reasons.push("ELEVATED_ML_SCORE");
  } else if (modelResult.rawScore < 0.2) {
    reasons.push("LOW_ML_SCORE");
  }

  // Evidence-based reasons
  if (features.has_password_field) {
    reasons.push("PASSWORD_FIELD_DETECTED");
  }

  if (features.has_otp_field) {
    reasons.push("OTP_FIELD_DETECTED");
  }

  if (features.has_card_field) {
    reasons.push("PAYMENT_CARD_FIELD_DETECTED");
  }

  if (features.has_cvv_field) {
    reasons.push("CVV_FIELD_DETECTED");
  }

  if (features.has_identity_field) {
    reasons.push("IDENTITY_DOCUMENT_FIELD_DETECTED");
  }

  if (features.has_bank_field) {
    reasons.push("BANK_ACCOUNT_FIELD_DETECTED");
  }

  if (features.cross_domain_form) {
    reasons.push("CROSS_DOMAIN_FORM");
  }

  if (features.form_count > 2) {
    reasons.push(`MULTIPLE_FORMS_${features.form_count}`);
  }

  if (features.input_count > 5) {
    reasons.push(`MANY_INPUT_FIELDS_${features.input_count}`);
  }

  // Evidence structure reasons
  if (evidence.scripts.length > 3) {
    reasons.push(`MULTIPLE_SCRIPTS_${evidence.scripts.length}`);
  }

  const crossDomainScripts = evidence.scripts.filter((s) => s.isCrossDomain);
  if (crossDomainScripts.length > 0) {
    reasons.push(`CROSS_DOMAIN_SCRIPTS_${crossDomainScripts.length}`);
  }

  // Service behavior comparison reasons
  const events = extractObservedEvents(evidence);
  const comparison = compareBehavior(evidence, events);
  if (comparison.matchedProfile && comparison.reasons && comparison.reasons.length > 0) {
    comparison.reasons.forEach((r) => {
      if (!reasons.includes(r)) {
        reasons.push(r);
      }
    });
  }

  return reasons.length > 0 ? reasons : ["INSUFFICIENT_DATA"];
}

/**
 * Perform comprehensive threat assessment.
 */
export function assessThreat(context: AssessmentContext): ThreatAssessment {
  const confidence = calculateConfidence(context);
  const reasons = generateReasons(context);
  const threatLevel = scoreToThreatLevel(context.modelResult.rawScore);

  return {
    threatLevel,
    score: context.modelResult.rawScore,
    confidence,
    evaluatedAt: Date.now(),
    reasons,
  };
}
