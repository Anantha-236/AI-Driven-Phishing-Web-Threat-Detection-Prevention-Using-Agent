/**
 * CAPSTONE-1 Declared Service Profiles Registry
 *
 * Maintains structured profiles of verified legitimate services,
 * their official domains, permitted capabilities, data categories, and purposes.
 */

export interface ServiceProfile {
  service_id: string;
  service_name: string;
  service_category: string;
  official_domains: string[];
  authentication_domains: string[];
  authorization_domains: string[];
  documented_data_categories: string[];
  documented_capabilities: string[];
  documented_permissions: string[];
  documented_purposes: string[];
  policy_source: string;
  policy_version: string;
  policy_date: string;
  profile_version: string;
}

export const DECLARED_SERVICE_PROFILES: Record<string, ServiceProfile> = {
  "bankone": {
    service_id: "bankone",
    service_name: "BankOne Financial",
    service_category: "banking",
    official_domains: ["bankone.com", "auth.bankone.com", "secure-bank.example.com"],
    authentication_domains: ["auth.bankone.com", "bankone.com"],
    authorization_domains: ["auth.bankone.com"],
    documented_data_categories: ["credentials", "account_number", "otp"],
    documented_capabilities: ["account_management", "wire_transfer"],
    documented_permissions: ["cookies", "storage"],
    documented_purposes: ["authentication", "transaction_processing"],
    policy_source: "https://bankone.com/privacy-policy",
    policy_version: "2026.1",
    policy_date: "2026-01-15",
    profile_version: "1.0.0",
  },
  "paypal": {
    service_id: "paypal",
    service_name: "PayPal Payment Services",
    service_category: "payments",
    official_domains: ["paypal.com", "services.paypal.com", "signin.paypal.com"],
    authentication_domains: ["signin.paypal.com", "paypal.com"],
    authorization_domains: ["paypal.com"],
    documented_data_categories: ["credentials", "card_data", "otp", "financial_records"],
    documented_capabilities: ["checkout", "p2p_transfer"],
    documented_permissions: ["notifications", "storage"],
    documented_purposes: ["payment_authorization", "fraud_prevention"],
    policy_source: "https://paypal.com/legal/privacy",
    policy_version: "2026.2",
    policy_date: "2026-02-01",
    profile_version: "1.0.0",
  },
  "google": {
    service_id: "google",
    service_name: "Google Accounts",
    service_category: "identity_provider",
    official_domains: ["google.com", "accounts.google.com", "myaccount.google.com"],
    authentication_domains: ["accounts.google.com"],
    authorization_domains: ["accounts.google.com"],
    documented_data_categories: ["credentials", "profile_data", "otp", "security_keys"],
    documented_capabilities: ["sso", "identity_federation"],
    documented_permissions: ["storage", "webauthn"],
    documented_purposes: ["user_authentication", "access_delegation"],
    policy_source: "https://policies.google.com/privacy",
    policy_version: "2026.1",
    policy_date: "2026-01-01",
    profile_version: "1.0.0",
  },
  "microsoft": {
    service_id: "microsoft",
    service_name: "Microsoft 365 / Entra",
    service_category: "productivity",
    official_domains: ["microsoft.com", "signin.microsoftonline.com", "portal.office.com", "login.microsoftonline.com"],
    authentication_domains: ["signin.microsoftonline.com", "login.microsoftonline.com"],
    authorization_domains: ["login.microsoftonline.com"],
    documented_data_categories: ["credentials", "enterprise_id", "otp"],
    documented_capabilities: ["enterprise_sso", "cloud_productivity"],
    documented_permissions: ["storage"],
    documented_purposes: ["corporate_authentication", "document_access"],
    policy_source: "https://privacy.microsoft.com",
    policy_version: "2026.1",
    policy_date: "2026-01-10",
    profile_version: "1.0.0",
  },
};

export function findProfileByDomain(domain: string): ServiceProfile | null {
  const lowerDomain = domain.toLowerCase();
  for (const profile of Object.values(DECLARED_SERVICE_PROFILES)) {
    if (profile.official_domains.some((d) => lowerDomain === d || lowerDomain.endsWith(`.${d}`))) {
      return profile;
    }
  }
  return null;
}

export function findProfileById(serviceId: string): ServiceProfile | null {
  return DECLARED_SERVICE_PROFILES[serviceId.toLowerCase()] || null;
}
