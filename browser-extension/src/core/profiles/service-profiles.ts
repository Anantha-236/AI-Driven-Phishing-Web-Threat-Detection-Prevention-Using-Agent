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

// Independent of the historical/example profiles above. Exact host matches only;
// an origin match establishes a registry association, never page safety or delegation.
export const LOGIN_ORIGINS = [
  { service: 'google', origin: 'https://accounts.google.com', source: 'https://accounts.google.com/', checked: '2026-09-10' },
  { service: 'paypal', origin: 'https://www.paypal.com', source: 'https://www.paypal.com/signin', checked: '2026-09-10' },
  { service: 'microsoft', origin: 'https://login.microsoftonline.com', source: 'https://login.microsoftonline.com/', checked: '2026-09-10' },
] as const;
export interface OriginIdentity {
  status: 'KNOWN_LOGIN_ORIGIN' | 'POSSIBLE_IMPERSONATION' | 'UNKNOWN';
  service: 'google' | 'paypal' | 'microsoft' | null;
}
export function identifyOrigin(origin: string | null): OriginIdentity {
  const unknown: OriginIdentity = { status: 'UNKNOWN', service: null };
  if (!origin) return unknown;
  try {
    const url = new URL(origin);
    if (!['https:', 'http:'].includes(url.protocol)) return unknown;
    const known = LOGIN_ORIGINS.find(entry => entry.origin === url.origin);
    if (known) return { status: 'KNOWN_LOGIN_ORIGIN', service: known.service };
    const host = url.hostname.toLowerCase();
    // A brand word embedded in another hostname is a clue, not proof of impersonation.
    // Exclude the corresponding real parent domain without extending trusted login scope.
    for (const service of ['google', 'paypal', 'microsoft'] as const) {
      const parents = service === 'microsoft' ? ['microsoft.com', 'microsoftonline.com'] : [`${service}.com`];
      if (parents.some(parent => host === parent || host.endsWith(`.${parent}`))) return unknown;
      if (host.split(/[.-]/).some(label => label.includes(service))) return { status: 'POSSIBLE_IMPERSONATION', service };
    }
    return unknown;
  } catch { return unknown; }
}

export function destinationStatus(pageOrigin: string | null, target: string | null) {
  if (!target) return 'UNKNOWN' as const;
  if (pageOrigin?.startsWith('https:') && target.startsWith('http:')) return 'HTTPS_DOWNGRADE' as const;
  if (target === pageOrigin) return 'SAME_ORIGIN' as const;
  if (identifyOrigin(target).status === 'KNOWN_LOGIN_ORIGIN') return 'KNOWN_LOGIN_ORIGIN' as const;
  return 'UNVERIFIED_CROSS_ORIGIN' as const;
}
