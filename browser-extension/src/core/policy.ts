/**
 * CAPSTONE-1 Policy Engine
 *
 * Deterministic mapping of threat assessments and contextual factors to enforcement actions.
 *
 * Policy rules:
 *  - BENIGN → ALLOW
 *  - SUSPICIOUS (low/moderate confidence) → WARN
 *  - SUSPICIOUS (high confidence / sensitive) → WARN or CONFIRM
 *  - MALICIOUS (high confidence > 0.8) → BLOCK
 *  - MALICIOUS (moderate confidence) → CONTAIN
 *  - INSUFFICIENT_EVIDENCE → ALLOW (never auto-block)
 */

import {
  ThreatAssessment,
  PolicyDecision,
  PolicyAction,
  EnforcementOutcome,
} from "./schema/types";

export interface PolicyContext {
  assessment: ThreatAssessment;
  pageDomain?: string;
  isSensitiveContext?: boolean; // login, payment, etc.
}

/**
 * Determine the enforcement action based on threat level and context.
 */
export function determinePolicyAction(
  context: PolicyContext
): {
  action: PolicyAction;
  outcome: EnforcementOutcome;
} {
  const { assessment } = context;

  switch (assessment.threatLevel) {
    case "benign":
      return {
        action: "ALLOW",
        outcome: "ALLOWED",
      };

    case "insufficient_evidence":
      return {
        action: "ALLOW",
        outcome: "ALLOWED",
      };

    case "suspicious":
      return {
        action: "WARN",
        outcome: "DECISION_ONLY",
      };

    case "malicious":
      if (assessment.confidence > 0.8) {
        return {
          action: "BLOCK",
          outcome: "DECISION_ONLY",
        };
      }
      return {
        action: "CONTAIN",
        outcome: "DECISION_ONLY",
      };

    default:
      return {
        action: "WARN",
        outcome: "DECISION_ONLY",
      };
  }
}

/**
 * Generate human-readable explanation for the policy decision.
 */
export function generatePolicyReason(
  assessment: ThreatAssessment,
  actionChoice: PolicyAction
): string {
  const confidenceLevel =
    assessment.confidence > 0.7
      ? "high confidence"
      : assessment.confidence > 0.5
        ? "moderate confidence"
        : "low confidence";

  const baseReason = `${assessment.threatLevel} threat (${confidenceLevel})`;

  switch (actionChoice) {
    case "ALLOW":
      return `${baseReason} - allowing page to load normally`;
    case "WARN":
      return `${baseReason} - requesting a warning`;
    case "BLOCK":
      return `${baseReason} - requesting blocking due to high-risk indicators`;
    case "CONTAIN":
      return `${baseReason} - requesting containment`;
    case "CONFIRM":
      return `${baseReason} - requiring confirmation before submission`;
    default:
      return `Policy action: ${actionChoice}`;
  }
}

/**
 * Make a policy decision based on threat assessment.
 */
export function makePolicy(
  context: PolicyContext
): PolicyDecision {
  const { action, outcome } = determinePolicyAction(context);
  const reason = generatePolicyReason(context.assessment, action);

  return {
    action,
    outcome,
    reason,
    timestamp: Date.now(),
  };
}
