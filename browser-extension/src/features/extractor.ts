import { EvidenceCollection, FeatureVector } from "../core/schema/types";

const KNOWN_BRANDS = [
  "google", "paypal", "apple", "microsoft", "amazon", "netflix",
  "facebook", "instagram", "bankone", "chase", "wellsfargo", "bankofamerica", "github", "dropbox", "stripe"
];

const SUSPICIOUS_TOKENS = [
  "login", "signin", "verify", "account", "update", "banking",
  "secure", "ebayisapi", "webscr", "cmd", "auth", "confirm", "wallet"
];

export function calculateEntropy(text: string): number {
  if (!text) return 0.0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  const len = text.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function isIpAddress(host: string): boolean {
  if (!host) return false;
  const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  return ipv4Pattern.test(host);
}

export function extractFeatureVector(evidence: EvidenceCollection): FeatureVector {
  const forms = evidence.forms ?? [];
  const inputs = evidence.inputs ?? [];
  const scripts = evidence.scripts ?? [];
  const requests = evidence.requests ?? [];
  const page = evidence.page;

  const urlStr = page?.url || "";
  let parsedUrl: URL | null = null;
  try {
    if (urlStr) parsedUrl = new URL(urlStr);
  } catch {
    parsedUrl = null;
  }

  const hostname = page?.domain || (parsedUrl ? parsedUrl.hostname : "");
  const pathname = parsedUrl ? parsedUrl.pathname : "";
  const query = parsedUrl ? parsedUrl.search.replace(/^\?/, "") : "";
  const fragment = parsedUrl ? parsedUrl.hash.replace(/^#/, "") : "";

  const pathClean = pathname.replace(/^\//, "");
  const labels = hostname.split(".").filter(Boolean);
  const subdomainCount = labels.length > 2 ? labels.length - 2 : 0;
  const pathSegments = pathname.split("/").filter(Boolean);
  const pathDepth = pathSegments.length;
  const queryParams = query.split("&").filter(Boolean);

  const specialChars = urlStr.match(/[^a-zA-Z0-9\s]/g) || [];
  const digitChars = urlStr.match(/\d/g) || [];
  const letterChars = urlStr.match(/[a-zA-Z]/g) || [];
  const encodedChars = urlStr.match(/%[0-9a-fA-F]{2}/g) || [];

  const entropy = calculateEntropy(urlStr);
  const ipAddressHost = isIpAddress(hostname) ? 1 : 0;
  const punycodePresent = hostname.toLowerCase().includes("xn--") ? 1 : 0;
  const atSymbolPresent = urlStr.includes("@") ? 1 : 0;
  const hyphenCount = (urlStr.match(/-/g) || []).length;
  const underscoreCount = (urlStr.match(/_/g) || []).length;

  const lowerUrl = urlStr.toLowerCase();

  const suspiciousTokenCount = SUSPICIOUS_TOKENS.reduce((acc, tok) => acc + (lowerUrl.includes(tok) ? 1 : 0), 0);
  const brandKeywordCount = KNOWN_BRANDS.reduce((acc, brand) => acc + (lowerUrl.includes(brand) ? 1 : 0), 0);

  const hasPasswordField = forms.some((f) => f.hasPasswordField) || inputs.some((i) => i.isPassword);
  const hasOtpField = forms.some((f) => f.hasOtpField) || inputs.some((i) => i.isOtp);
  const crossDomainForm = forms.some((f) => f.isCrossDomain);

  const hasEmailField = forms.some((f) => f.detectedDataTypes?.includes("EMAIL")) || inputs.some((i) => i.detectedDataTypes?.includes("EMAIL"));
  const hasUsernameField = forms.some((f) => f.detectedDataTypes?.includes("USERNAME")) || inputs.some((i) => i.detectedDataTypes?.includes("USERNAME"));
  const hasPhoneField = forms.some((f) => f.detectedDataTypes?.includes("PHONE")) || inputs.some((i) => i.detectedDataTypes?.includes("PHONE"));
  const hasCardField = forms.some((f) => f.detectedDataTypes?.includes("CARD")) || inputs.some((i) => i.detectedDataTypes?.includes("CARD"));
  const hasCvvField = forms.some((f) => f.detectedDataTypes?.includes("CVV")) || inputs.some((i) => i.detectedDataTypes?.includes("CVV"));
  const hasIdentityField = forms.some((f) => f.detectedDataTypes?.includes("ID")) || inputs.some((i) => i.detectedDataTypes?.includes("ID"));
  const hasBankField = forms.some((f) => f.detectedDataTypes?.includes("BANK_ACCOUNT")) || inputs.some((i) => i.detectedDataTypes?.includes("BANK_ACCOUNT"));
  const hasFileUpload = forms.some((f) => f.detectedDataTypes?.includes("FILE_UPLOAD")) || inputs.some((i) => i.detectedDataTypes?.includes("FILE_UPLOAD"));

  const formCount = forms.length;
  const inputCount = inputs.length;

  return {
    has_password_field: hasPasswordField,
    has_otp_field: hasOtpField,
    cross_domain_form: crossDomainForm,
    form_count: formCount,
    input_count: inputCount,
    has_email_field: hasEmailField,
    has_username_field: hasUsernameField,
    has_phone_field: hasPhoneField,
    has_card_field: hasCardField,
    has_cvv_field: hasCvvField,
    has_identity_field: hasIdentityField,
    has_bank_field: hasBankField,
    has_file_upload: hasFileUpload,

    // Origin-only prototype features; path/query features are unavailable, not research-model parity.
    url_length: urlStr.length,
    hostname_length: hostname.length,
    path_length: pathClean.length,
    query_length: query.length,
    fragment_length: fragment.length,
    subdomain_count: subdomainCount,
    path_depth: pathDepth,
    query_parameter_count: queryParams.length,
    special_character_count: specialChars.length,
    digit_count: digitChars.length,
    letter_count: letterChars.length,
    encoded_character_count: encodedChars.length,
    entropy,
    ip_address_host: ipAddressHost,
    punycode_present: punycodePresent,
    at_symbol_present: atSymbolPresent,
    hyphen_count: hyphenCount,
    underscore_count: underscoreCount,
    suspicious_token_count: suspiciousTokenCount,
    brand_keyword_count: brandKeywordCount,
    domain_length: hostname.length,
    domain_is_ip: ipAddressHost,
    punycode: punycodePresent,
    dom_element_count: formCount + inputCount + scripts.length + requests.length,
    external_script_count: scripts.filter((s) => s.isCrossDomain).length,
    inline_script_count: scripts.filter((s) => s.isInline).length,
    login_form_detected: hasPasswordField ? 1 : 0,
    password_field_detected: hasPasswordField ? 1 : 0,
    otp_field_detected: hasOtpField ? 1 : 0,
    payment_field_detected: hasCardField ? 1 : 0,
    identity_field_detected: hasIdentityField ? 1 : 0,
    same_origin_submission: formCount > 0 && !crossDomainForm ? 1 : 0,
    cross_origin_submission: crossDomainForm ? 1 : 0,
    cross_registrable_domain_submission: crossDomainForm ? 1 : 0,
    form_secure_transport: parsedUrl?.protocol === "https:" ? 1 : 0,
    field_count: inputCount,
    credential_requested: hasPasswordField ? 1 : 0,
    password_requested: hasPasswordField ? 1 : 0,
    otp_requested: hasOtpField ? 1 : 0,
    financial_data_requested: hasCardField || hasBankField ? 1 : 0,
    identity_data_requested: hasIdentityField ? 1 : 0,
  };
}
