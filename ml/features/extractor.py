from __future__ import annotations

import math
import re
from urllib.parse import urlparse

KNOWN_BRANDS = [
    "google", "paypal", "apple", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "bankone", "chase", "wellsfargo", "bankofamerica", "github", "dropbox", "stripe"
]

SUSPICIOUS_TOKENS = [
    "login", "signin", "verify", "account", "update", "banking",
    "secure", "ebayisapi", "webscr", "cmd", "auth", "confirm", "wallet"
]


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def is_ip_address(host: str) -> bool:
    if not host:
        return False
    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ipv4_pattern, host))


def extract_features(sample: dict) -> dict:
    url_str = str(sample.get("url", ""))
    parsed = urlparse(url_str) if url_str else None

    hostname = str(sample.get("hostname", parsed.hostname if parsed and parsed.hostname else ""))
    pathname = parsed.path if parsed else ""
    query = parsed.query if parsed else ""
    fragment = parsed.fragment if parsed else ""

    url_length = len(url_str)
    hostname_length = len(hostname)
    path_clean = pathname.lstrip("/")
    path_length = len(path_clean)
    query_length = len(query)
    fragment_length = len(fragment)

    labels = [p for p in hostname.split(".") if p]
    subdomain_count = max(0, len(labels) - 2) if len(labels) > 2 else 0

    path_segments = [seg for seg in pathname.split("/") if seg]
    path_depth = len(path_segments)

    query_params = [p for p in query.split("&") if p]
    query_parameter_count = len(query_params)

    special_chars = re.findall(r"[^a-zA-Z0-9\s]", url_str)
    special_character_count = len(special_chars)
    digit_count = len(re.findall(r"\d", url_str))
    letter_count = len(re.findall(r"[a-zA-Z]", url_str))
    encoded_character_count = len(re.findall(r"%[0-9a-fA-F]{2}", url_str))

    entropy = calculate_entropy(url_str)
    ip_address_host = 1 if is_ip_address(hostname) else 0
    punycode_present = 1 if "xn--" in hostname.lower() else 0
    at_symbol_present = 1 if "@" in url_str else 0
    hyphen_count = url_str.count("-")
    underscore_count = url_str.count("_")

    suspicious_token_count = sum(1 for tok in SUSPICIOUS_TOKENS if tok in url_str.lower())
    brand_keyword_count = sum(1 for brand in KNOWN_BRANDS if brand in url_str.lower())

    claimed_service = str(sample.get("claimed_service", sample.get("claimed_service_category", "unknown"))).lower()
    known_brand = str(sample.get("known_brand", "")).lower()
    official_domain = str(sample.get("official_domain", "")).lower()

    brand_domain_mismatch = 1 if (known_brand and known_brand in url_str.lower() and known_brand not in hostname.lower()) else 0

    domain_length = len(hostname)
    subdomain_length = len(".".join(labels[:-2])) if len(labels) > 2 else 0
    domain_is_ip = ip_address_host
    punycode = punycode_present
    domain_similarity_to_brand = 1.0 if (known_brand and known_brand in hostname.lower()) else 0.0
    homograph_indicator = 1 if (punycode_present or "%" in hostname) else 0
    domain_known_to_registry = 1 if (official_domain and official_domain in hostname.lower()) else 0
    domain_matches_claimed_service = 1 if (official_domain and official_domain in hostname.lower()) else 0

    # DOM & Form features
    form_count = int(sample.get("form_count", 1 if sample.get("login_form_detected") or sample.get("password_field_detected") else 0))
    input_count = int(sample.get("input_count", 2 if sample.get("password_field_detected") else (1 if sample.get("login_form_detected") else 0)))
    button_count = form_count
    iframe_count = int(sample.get("iframe_count", 0))
    hidden_element_count = int(sample.get("hidden_element_count", 0))
    external_resource_count = int(sample.get("external_resource_count", 1 if sample.get("cross_domain_redirect") else 0))
    external_script_count = int(sample.get("external_script_count", 0))
    inline_script_count = int(sample.get("inline_script_count", 0))
    dom_element_count = form_count + input_count + button_count + external_resource_count

    login_form_detected = int(bool(sample.get("login_form_detected", form_count > 0)))
    payment_form_detected = int(bool(sample.get("payment_form_detected", 0)))
    registration_form_detected = int(bool(sample.get("registration_form_detected", 0)))
    password_form_detected = int(bool(sample.get("password_form_detected", sample.get("password_field_detected", 0))))
    file_upload_form_detected = int(bool(sample.get("file_upload_form_detected", 0)))

    field_count = input_count
    sensitive_field_count = int(bool(sample.get("password_field_detected", 0))) + int(bool(sample.get("otp_field_detected", 0)))
    hidden_field_count = int(sample.get("hidden_field_count", 0))
    same_origin_submission = 1 if (form_count > 0 and not sample.get("cross_origin_submission", sample.get("cross_domain_form", 0))) else 0
    cross_origin_submission = int(bool(sample.get("cross_origin_submission", sample.get("cross_domain_form", 0))))
    cross_registrable_domain_submission = cross_origin_submission
    form_secure_transport = 1 if (parsed and parsed.scheme == "https") else 0
    autocomplete_present = int(bool(sample.get("autocomplete_present", 1 if login_form_detected else 0)))
    password_field_detected = int(bool(sample.get("password_field_detected", 0)))
    otp_field_detected = int(bool(sample.get("otp_field_detected", 0)))
    payment_field_detected = int(bool(sample.get("payment_field_detected", 0)))
    identity_field_detected = int(bool(sample.get("identity_field_detected", 0)))

    # Behavior & Redirect features
    redirect_count = int(sample.get("redirect_count", 0))
    redirect_chain_length = redirect_count
    cross_domain_redirect = int(bool(sample.get("cross_domain_redirect", 0)))
    cross_registrable_domain_redirect = cross_domain_redirect
    redirect_to_ip = 1 if (cross_domain_redirect and ip_address_host) else 0
    redirect_to_punycode = 1 if (cross_domain_redirect and punycode_present) else 0
    redirect_to_similar_brand = 1 if (cross_domain_redirect and brand_domain_mismatch) else 0
    redirect_chain_contains_unknown_domain = 1 if (cross_domain_redirect and not domain_known_to_registry) else 0

    # Context & Service Identity
    claimed_service_category = claimed_service
    known_brand_val = known_brand if known_brand else "unknown"
    official_domain_match = domain_known_to_registry
    authentication_domain_match = 1 if (domain_known_to_registry and (login_form_detected or password_field_detected)) else 0
    authorization_domain_match = official_domain_match
    brand_impersonation_indicator = int(bool(sample.get("brand_impersonation_indicator", brand_domain_mismatch)))
    identity_status = "verified" if official_domain_match else ("unknown" if not known_brand else "mismatched")

    # Data Behavior
    credential_requested = int(bool(sample.get("credential_requested", login_form_detected or password_field_detected)))
    password_requested = int(bool(sample.get("password_requested", password_field_detected)))
    otp_requested = int(bool(sample.get("otp_requested", otp_field_detected)))
    financial_data_requested = int(bool(sample.get("financial_data_requested", payment_field_detected)))
    identity_data_requested = int(bool(sample.get("identity_data_requested", identity_field_detected)))
    personal_data_requested = int(bool(sample.get("personal_data_requested", credential_requested)))
    device_data_requested = int(bool(sample.get("device_data_requested", 0)))
    unexpected_data_request = int(bool(sample.get("unexpected_data_request", (credential_requested and not official_domain_match))))
    purpose_mismatch = int(bool(sample.get("purpose_mismatch", 0)))
    possibly_excessive = int(bool(sample.get("possibly_excessive", input_count > 5)))
    deceptive_collection_indicator = int(bool(sample.get("deceptive_collection_indicator", (cross_origin_submission and password_field_detected))))

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "fragment_length": fragment_length,
        "subdomain_count": subdomain_count,
        "path_depth": path_depth,
        "query_parameter_count": query_parameter_count,
        "special_character_count": special_character_count,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "encoded_character_count": encoded_character_count,
        "entropy": entropy,
        "ip_address_host": ip_address_host,
        "punycode_present": punycode_present,
        "at_symbol_present": at_symbol_present,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "suspicious_token_count": suspicious_token_count,
        "brand_keyword_count": brand_keyword_count,
        "brand_domain_mismatch": brand_domain_mismatch,
        "domain_length": domain_length,
        "subdomain_length": subdomain_length,
        "domain_is_ip": domain_is_ip,
        "punycode": punycode,
        "domain_similarity_to_brand": domain_similarity_to_brand,
        "homograph_indicator": homograph_indicator,
        "domain_known_to_registry": domain_known_to_registry,
        "domain_matches_claimed_service": domain_matches_claimed_service,
        "dom_element_count": dom_element_count,
        "form_count": form_count,
        "input_count": input_count,
        "button_count": button_count,
        "iframe_count": iframe_count,
        "hidden_element_count": hidden_element_count,
        "external_resource_count": external_resource_count,
        "external_script_count": external_script_count,
        "inline_script_count": inline_script_count,
        "login_form_detected": login_form_detected,
        "payment_form_detected": payment_form_detected,
        "registration_form_detected": registration_form_detected,
        "password_form_detected": password_form_detected,
        "file_upload_form_detected": file_upload_form_detected,
        "field_count": field_count,
        "sensitive_field_count": sensitive_field_count,
        "hidden_field_count": hidden_field_count,
        "same_origin_submission": same_origin_submission,
        "cross_origin_submission": cross_origin_submission,
        "cross_registrable_domain_submission": cross_registrable_domain_submission,
        "form_secure_transport": form_secure_transport,
        "autocomplete_present": autocomplete_present,
        "password_field_detected": password_field_detected,
        "otp_field_detected": otp_field_detected,
        "payment_field_detected": payment_field_detected,
        "identity_field_detected": identity_field_detected,
        "redirect_count": redirect_count,
        "redirect_chain_length": redirect_chain_length,
        "cross_domain_redirect": cross_domain_redirect,
        "cross_registrable_domain_redirect": cross_registrable_domain_redirect,
        "redirect_to_ip": redirect_to_ip,
        "redirect_to_punycode": redirect_to_punycode,
        "redirect_to_similar_brand": redirect_to_similar_brand,
        "redirect_chain_contains_unknown_domain": redirect_chain_contains_unknown_domain,
        "claimed_service_category": claimed_service_category,
        "known_brand": known_brand_val,
        "official_domain_match": official_domain_match,
        "authentication_domain_match": authentication_domain_match,
        "authorization_domain_match": authorization_domain_match,
        "brand_impersonation_indicator": brand_impersonation_indicator,
        "identity_status": identity_status,
        "credential_requested": credential_requested,
        "password_requested": password_requested,
        "otp_requested": otp_requested,
        "financial_data_requested": financial_data_requested,
        "identity_data_requested": identity_data_requested,
        "personal_data_requested": personal_data_requested,
        "device_data_requested": device_data_requested,
        "unexpected_data_request": unexpected_data_request,
        "purpose_mismatch": purpose_mismatch,
        "possibly_excessive": possibly_excessive,
        "deceptive_collection_indicator": deceptive_collection_indicator,
    }
