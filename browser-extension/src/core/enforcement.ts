/**
 * CAPSTONE-1 Enforcement Module
 *
 * Orchestrates the complete detection pipeline:
 * Evidence → Features → ML Score → Assessment → Policy → Enforcement
 *
 * Responsible for:
 * - Coordinating adapter selection
 * - Running complete inference pipeline
 * - Generating enforcement decisions
 * - Messaging UI with results
 */

import { EvidenceCollection, FeatureVector, ModelResult, ExtensionMessage } from "../core/schema/types";
import { assessThreat, AssessmentContext } from "../core/assessment";
import { makePolicy, PolicyContext } from "../core/policy";
import { extractFeatureVector } from "../features/extractor";

export interface DetectionResult {
  evidence: EvidenceCollection;
  features: FeatureVector;
  modelResult: ModelResult;
  threat: Awaited<ReturnType<typeof assessThreat>>;
  policy: Awaited<ReturnType<typeof makePolicy>>;
}

/**
 * Execute the complete detection pipeline for collected evidence.
 *
 * This is the main orchestration function that coordinates all
 * detection components into one cohesive system.
 */
export async function runDetectionPipeline(
  evidence: EvidenceCollection,
  adapter: { infer: (features: FeatureVector) => Promise<ModelResult> }
): Promise<DetectionResult> {
  // Step 1: Extract features from evidence
  const features = extractFeatureVector(evidence);

  // Step 2: Run ML inference
  const modelResult = await adapter.infer(features);

  // Step 3: Assess threat
  const assessmentContext: AssessmentContext = {
    modelResult,
    evidence,
    features,
  };
  const threat = assessThreat(assessmentContext);

  // Step 4: Make policy decision
  const policyContext: PolicyContext = {
    assessment: threat,
    pageDomain: evidence.page.domain,
    // could check if page is sensitive context (login, payment, etc)
  };
  const policy = makePolicy(policyContext);

  return {
    evidence,
    features,
    modelResult,
    threat,
    policy,
  };
}

/**
 * Convert a detection result into a message for UI.
 *
 * The UI needs:
 * - Threat level
 * - Score
 * - Confidence
 * - Reasons why
 * - Recommended action
 */
export function createDetectionMessage(
  result: DetectionResult
): ExtensionMessage<{
  threatLevel: string;
  score: number;
  confidence: number;
  reasons: string[];
  action: string;
  outcome: string;
  domain: string;
  requestedDataTypes: string[];
}> {
  return {
    type: "POLICY_DECISION",
    source: "service-worker",
    target: "content-script",
    payload: {
      threatLevel: result.threat.threatLevel,
      score: result.modelResult.rawScore,
      confidence: result.threat.confidence,
      reasons: result.threat.reasons,
      action: result.policy.action,
      outcome: result.policy.outcome,
      domain: result.evidence.page.domain,
      requestedDataTypes: result.evidence.requestedDataTypes || [],
    },
    timestamp: Date.now(),
  };
}
