import { DataTypeCategory } from "../schema/types";

export interface InputStructuralMetadata {
  inputType: string;
  name: string;
  idAttribute: string;
  autocomplete: string;
  placeholder?: string;
  ariaLabel?: string;
  accept?: string;
  capture?: string;
  isRequired?: boolean;
}

/**
 * Privacy-Safe Structural Data-Type Classifier
 *
 * Classifies the type of information requested by a field using ONLY
 * structural HTML attributes and metadata.
 *
 * STRICT PRIVACY MANDATE:
 * NEVER reads or touches element.value, innerText, textContent, or secret values.
 */
export function classifyInputDataTypes(input: InputStructuralMetadata): DataTypeCategory[] {
  const categories = new Set<DataTypeCategory>();

  const type = (input.inputType || "").toLowerCase().trim();
  const name = (input.name || "").toLowerCase().trim();
  const id = (input.idAttribute || "").toLowerCase().trim();
  const auto = (input.autocomplete || "").toLowerCase().trim();
  const placeholder = (input.placeholder || "").toLowerCase().trim();
  const aria = (input.ariaLabel || "").toLowerCase().trim();
  const accept = (input.accept || "").toLowerCase().trim();
  const capture = (input.capture || "").toLowerCase().trim();

  const combinedIdentifiers = `${name} ${id} ${placeholder} ${aria}`;

  // 1. PASSWORD
  if (
    type === "password" ||
    auto.includes("current-password") ||
    auto.includes("new-password") ||
    /\b(password|passwd|pwd|secret)\b/.test(combinedIdentifiers)
  ) {
    categories.add("PASSWORD");
  }

  // 2. OTP
  if (
    type === "one-time-code" ||
    auto.includes("one-time-code") ||
    /\b(otp|2fa|mfa|totp|passcode|token|verification[-_]?code|auth[-_]?code|security[-_]?code|pin[-_]?code)\b/.test(combinedIdentifiers)
  ) {
    categories.add("OTP");
  }

  // 3. EMAIL
  if (
    type === "email" ||
    auto.includes("email") ||
    /\b(email|e-mail|user_email|useremail|mail)\b/.test(combinedIdentifiers)
  ) {
    categories.add("EMAIL");
  }

  // 4. USERNAME
  if (
    auto === "username" ||
    auto === "nickname" ||
    auto === "webauthn" ||
    (/\b(username|user_id|userid|login_id|account_name|login)\b/.test(combinedIdentifiers) &&
      !categories.has("PASSWORD") &&
      !categories.has("EMAIL"))
  ) {
    categories.add("USERNAME");
  }

  // 5. PHONE
  if (
    type === "tel" ||
    auto.includes("tel") ||
    auto.includes("mobile") ||
    /\b(phone|telephone|mobile|cellphone|cell|tel_num)\b/.test(combinedIdentifiers)
  ) {
    categories.add("PHONE");
  }

  // 6. ADDRESS
  if (
    auto.includes("address") ||
    auto.includes("street-address") ||
    auto.includes("address-line1") ||
    auto.includes("address-line2") ||
    auto.includes("address-level1") ||
    auto.includes("address-level2") ||
    auto.includes("postal-code") ||
    auto.includes("country") ||
    auto.includes("zip") ||
    /\b(address|street|addr|city|state|zipcode|postal|postalcode|country)\b/.test(combinedIdentifiers)
  ) {
    categories.add("ADDRESS");
  }

  // 7. DATE_OF_BIRTH
  if (
    auto.includes("bday") ||
    (/\b(dob|birth[-_]?date|birthdate|birthday|date[-_]?of[-_]?birth)\b/.test(combinedIdentifiers) &&
      (type === "date" || type === "text" || type === "number" || !type))
  ) {
    categories.add("DATE_OF_BIRTH");
  }

  // 8. IDENTITY_DOCUMENT
  if (
    auto.includes("id-number") ||
    /\b(ssn|social[-_]?security|passport|national[-_]?id|driver[-_]?license|id[-_]?number|aadhaar|tax[-_]?id|nin|gov[-_]?id)\b/.test(combinedIdentifiers)
  ) {
    categories.add("IDENTITY_DOCUMENT");
  }

  // 9. PAYMENT_CARD
  if (
    auto.includes("cc-number") ||
    auto.includes("cc-type") ||
    /\b(card[-_]?number|cc[-_]?number|cardnumber|cc_num|creditcard|debitcard|card_num|pan_number)\b/.test(combinedIdentifiers)
  ) {
    categories.add("PAYMENT_CARD");
  }

  // 10. CARD_EXPIRY
  if (
    auto.includes("cc-exp") ||
    auto.includes("cc-exp-month") ||
    auto.includes("cc-exp-year") ||
    /\b(exp[-_]?date|cc[-_]?exp|card[-_]?exp|expiry|expiration|exp_month|exp_year)\b/.test(combinedIdentifiers)
  ) {
    categories.add("CARD_EXPIRY");
  }

  // 11. CVV
  if (
    auto.includes("cc-csc") ||
    auto.includes("cc-cvc") ||
    auto.includes("cc-cvv") ||
    /\b(cvv|cvc|csc|cvv2|cvc2|security[-_]?code|card[-_]?code)\b/.test(combinedIdentifiers)
  ) {
    categories.add("CVV");
  }

  // 12. BANK_ACCOUNT
  if (
    /\b(iban|swift|bic|routing[-_]?number|bank[-_]?account|account[-_]?number|sort[-_]?code|acc[-_]?num)\b/.test(combinedIdentifiers)
  ) {
    categories.add("BANK_ACCOUNT");
  }

  // 13. FILE_UPLOAD
  if (type === "file") {
    categories.add("FILE_UPLOAD");
  }

  // 14. CAMERA
  if (
    capture === "user" ||
    capture === "environment" ||
    capture === "camera" ||
    ((accept.includes("video") || accept.includes("image")) && Boolean(capture)) ||
    /\b(camera|webcam|photo_capture)\b/.test(combinedIdentifiers)
  ) {
    categories.add("CAMERA");
  }

  // 15. MICROPHONE
  if (
    capture === "microphone" ||
    (accept.includes("audio") && Boolean(capture)) ||
    /\b(microphone|audio_capture|voice_record)\b/.test(combinedIdentifiers)
  ) {
    categories.add("MICROPHONE");
  }

  // 16. LOCATION
  if (
    type === "location" ||
    /\b(latitude|longitude|coords|geolocation|geo_lat|geo_lon)\b/.test(combinedIdentifiers)
  ) {
    categories.add("LOCATION");
  }

  return Array.from(categories);
}
