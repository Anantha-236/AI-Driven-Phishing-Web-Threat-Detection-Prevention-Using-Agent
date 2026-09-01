/**
 * CAPSTONE-1 Observed Service Behavior
 *
 * Represents observed events and capabilities extracted from runtime Evidence.
 */

import { EvidenceCollection } from "../schema/types";

export type ObservationStatus = "OBSERVED" | "VERIFIED" | "INFERRED" | "UNKNOWN" | "NOT_OBSERVABLE";

export interface ObservedBehaviorEvent {
  event_id: string;
  service_id?: string;
  page_id: string;
  artifact_id: string;
  timestamp: number;
  event_type: "form_submission" | "credential_input" | "otp_input" | "script_load" | "navigation";
  data_category: "credentials" | "financial" | "identity" | "personal" | "general";
  data_subtype: string;
  action: string;
  destination: string;
  user_action_context: string;
  consent_status: "granted" | "implied" | "not_requested" | "unknown";
  authorization_status: "authorized" | "unauthorized" | "unknown";
  observation_status: ObservationStatus;
  evidence_ids: string[];
}

export function extractObservedEvents(evidence: EvidenceCollection): ObservedBehaviorEvent[] {
  const events: ObservedBehaviorEvent[] = [];
  const pageId = evidence.page.id;

  // Forms and Inputs observation
  evidence.forms.forEach((form) => {
    const hasPassword = form.hasPasswordField;
    const hasOtp = form.hasOtpField;
    const destination = form.action || evidence.page.domain;

    let dataCategory: ObservedBehaviorEvent["data_category"] = "general";
    let dataSubtype = "general_input";
    let eventType: ObservedBehaviorEvent["event_type"] = "form_submission";

    if (hasPassword && hasOtp) {
      dataCategory = "credentials";
      dataSubtype = "mfa_login";
      eventType = "credential_input";
    } else if (hasPassword) {
      dataCategory = "credentials";
      dataSubtype = "password_login";
      eventType = "credential_input";
    } else if (hasOtp) {
      dataCategory = "credentials";
      dataSubtype = "otp_verification";
      eventType = "otp_input";
    }

    events.push({
      event_id: `ev-${form.id}`,
      page_id: pageId,
      artifact_id: form.id,
      timestamp: form.timestamp,
      event_type: eventType,
      data_category: dataCategory,
      data_subtype: dataSubtype,
      action: form.method || "POST",
      destination,
      user_action_context: "page_interaction",
      consent_status: "implied",
      authorization_status: form.isCrossDomain ? "unauthorized" : "authorized",
      observation_status: "OBSERVED",
      evidence_ids: [form.id, ...form.inputIds],
    });
  });

  return events;
}
