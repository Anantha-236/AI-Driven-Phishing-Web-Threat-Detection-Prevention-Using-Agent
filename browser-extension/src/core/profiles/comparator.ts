/**
 * CAPSTONE-1 Service Behavior Comparator
 *
 * Compares declared service profile against observed runtime browser evidence.
 */

import { ServiceProfile, findProfileByDomain } from "./service-profiles";
import { ObservedBehaviorEvent } from "./observed-behavior";
import { EvidenceCollection } from "../schema/types";

export type BehaviorAssessmentOutcome =
  | "EXPECTED"
  | "UNEXPECTED"
  | "POSSIBLY_EXCESSIVE"
  | "PURPOSE_MISMATCH"
  | "IDENTITY_MISMATCH"
  | "DECEPTIVE_INDICATOR"
  | "UNKNOWN";

export interface ComparisonResult {
  outcome: BehaviorAssessmentOutcome;
  matchedProfile: ServiceProfile | null;
  reasons: string[];
  riskScoreModifier: number; // -0.2 to +0.5
}

export function compareBehavior(evidence: EvidenceCollection, events: ObservedBehaviorEvent[]): ComparisonResult {
  const domain = evidence.page.domain;
  const profile = findProfileByDomain(domain);

  // If service is unknown in declared profile registry
  if (!profile) {
    // Check if domain resembles known brands (homograph / mismatch)
    const forms = evidence.forms;
    const hasPassword = forms.some((f) => f.hasPasswordField);
    const isCrossDomain = forms.some((f) => f.isCrossDomain);

    if (hasPassword && isCrossDomain) {
      return {
        outcome: "DECEPTIVE_INDICATOR",
        matchedProfile: null,
        reasons: ["UNKNOWN_DOMAIN_COLLECTING_CREDENTIALS_CROSS_ORIGIN"],
        riskScoreModifier: 0.35,
      };
    }

    return {
      outcome: "UNKNOWN",
      matchedProfile: null,
      reasons: ["SERVICE_PROFILE_UNREGISTERED"],
      riskScoreModifier: 0.0,
    };
  }

  const reasons: string[] = [];
  let isMismatch = false;
  let isExcessive = false;

  for (const event of events) {
    // Check destination vs official domains
    if (event.destination && !event.destination.startsWith("/")) {
      try {
        const destUrl = new URL(event.destination, evidence.page.url);
        const destHost = destUrl.hostname;
        const matchesOfficial = profile.official_domains.some(
          (d) => destHost === d || destHost.endsWith(`.${d}`)
        );

        if (!matchesOfficial) {
          isMismatch = true;
          reasons.push(`DESTINATION_MISMATCH_${destHost}`);
        }
      } catch {
        // Invalid destination URL
      }
    }

    // Check data category against documented categories
    if (!profile.documented_data_categories.includes(event.data_category) && event.data_category !== "general") {
      isExcessive = true;
      reasons.push(`UNDOCUMENTED_DATA_CATEGORY_${event.data_category}`);
    }
  }

  if (isMismatch) {
    return {
      outcome: "IDENTITY_MISMATCH",
      matchedProfile: profile,
      reasons: reasons.length > 0 ? reasons : ["DOMAIN_NOT_AUTHORIZED_FOR_SERVICE"],
      riskScoreModifier: 0.4,
    };
  }

  if (isExcessive) {
    return {
      outcome: "POSSIBLY_EXCESSIVE",
      matchedProfile: profile,
      reasons,
      riskScoreModifier: 0.2,
    };
  }

  return {
    outcome: "EXPECTED",
    matchedProfile: profile,
    reasons: ["MATCHES_DECLARED_SERVICE_PROFILE"],
    riskScoreModifier: -0.2,
  };
}
