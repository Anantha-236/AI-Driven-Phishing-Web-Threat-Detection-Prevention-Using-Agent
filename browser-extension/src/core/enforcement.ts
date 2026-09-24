/**
 * CAPSTONE-1 Enforcement Module
 *
 * Legacy snapshot detection remains telemetry-only. Known-threat protection is
 * delegated to a provider-neutral reputation module and Stage A containment is
 * exposed as a separate executor for later agent orchestration.
 */

import {
  EvidenceCollection,
  FeatureVector,
  ModelResult,
  ExtensionMessage,
} from "../core/schema/types";
import { assessThreat, AssessmentContext } from "../core/assessment";
import { makePolicy, PolicyContext } from "../core/policy";
import { extractFeatureVector } from "../features/extractor";
import {
  compilePhishingRules,
  installOpenPhishProtection,
  PHISHING_FEED_URL,
} from "./reputation/openphish";

export type { ProtectionStatus } from "./reputation/openphish";
export { compilePhishingRules, PHISHING_FEED_URL };
export { createSessionContainment } from "./enforcement/session-containment";

/**
 * Compatibility wrapper used by the current service worker and popup.
 *
 * The returned API retains `status()` and `refresh()` while also exposing a
 * provider-neutral exact lookup for later risk-fusion integration.
 */
export function installThreatBlocking() {
  return installOpenPhishProtection();
}

export interface DetectionResult {
  evidence: EvidenceCollection;
  features: FeatureVector;
  modelResult: ModelResult;
  threat: Awaited<ReturnType<typeof assessThreat>>;
  policy: Awaited<ReturnType<typeof makePolicy>>;
}

/**
 * Execute the compatibility snapshot pipeline.
 *
 * Current browser security decisions are owned by the typed-event/context path;
 * this pipeline remains for historical observation telemetry.
 */
export async function runDetectionPipeline(
  evidence: EvidenceCollection,
  adapter: { infer: (features: FeatureVector) => Promise<ModelResult> },
): Promise<DetectionResult> {
  const features = extractFeatureVector(evidence);
  const modelResult = await adapter.infer(features);

  const assessmentContext: AssessmentContext = {
    modelResult,
    evidence,
    features,
  };
  const threat = assessThreat(assessmentContext);

  const policyContext: PolicyContext = {
    assessment: threat,
    pageDomain: evidence.page.domain,
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

export function createDetectionMessage(
  result: DetectionResult,
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
