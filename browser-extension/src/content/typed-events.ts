// M1 DOM event semantics adapted to the existing CAPSTONE collector/observer.
// This module creates no observer and never reads field values.
import { classifyInputDataTypes } from '../core/evidence/data-type-classifier';
import { observation, Observation, safeOrigin, SensitiveType } from '../core/tsfeg';
import { destinationStatus } from '../core/profiles/service-profiles';

// Categorize page-authored semantics locally. Never export text or inspect the
// text/value of form controls or editable regions. This is a claimed purpose,
// not a verified service identity or a guarantee that the page is legitimate.
export function inferPagePurpose(doc: Document): NonNullable<Observation['page_purpose']> {
  let semantics = '';
  for (const node of Array.from(doc.querySelectorAll('title,h1,h2,button')).slice(0, 40)) {
    if (node.closest('input,textarea,select,[contenteditable],script,style,template')) continue;
    const walker = doc.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    let child: Node | null;
    let visited = 0;
    while ((child = walker.nextNode()) && visited++ < 80 && semantics.length < 2048) {
      if (!child.parentElement?.closest('input,textarea,select,[contenteditable],script,style,template')) {
        semantics += ' ' + (child.nodeValue ?? '').slice(0, 120);
      }
    }
    if (semantics.length >= 2048) break;
  }
  const text = semantics.toLowerCase();
  const matches: Array<NonNullable<Observation['page_purpose']>> = [];
  if (/\b(checkout|payment|pay now|billing)\b/.test(text)) matches.push('PAYMENT');
  if (/\b(reset password|forgot password|recover(?:y| account)|account recovery)\b/.test(text)) matches.push('RECOVERY');
  if (/\b(sign[ -]?up|create (?:an? )?account|register|registration)\b/.test(text)) matches.push('SIGNUP');
  if (/\b(log[ -]?in|sign[ -]?in|authenticate|authentication)\b/.test(text)) matches.push('LOGIN');
  if (/\b(identity verification|verify (?:your )?identity)\b/.test(text)) matches.push('IDENTITY_VERIFICATION');
  if (/\b(download|software update)\b/.test(text)) matches.push('DOWNLOAD');
  if (/\b(article|news|documentation|about us)\b/.test(text)) matches.push('INFORMATIONAL');
  // Conflicting labels are common on real pages. Do not invent certainty.
  return matches.length === 1 ? matches[0] : 'UNKNOWN';
}
export function createTypedEvents(doc: Document, send: (events: Observation[]) => void) {
  let agentRequiresConfirmation = false;
  const ids = new WeakMap<Element, string>();
  const discovered = new WeakMap<Element, string>();
  const targets = new WeakMap<HTMLFormElement, string | null>();
  const interactedTargets = new WeakMap<HTMLFormElement, string | null>();
  let nextId = 0;
  let lastPurpose: Observation['page_purpose'] | undefined;
  function id(el: Element, prefix: string) { if (!ids.has(el)) ids.set(el, `${prefix}-${++nextId}`); return ids.get(el)!; }
  function category(el: Element): SensitiveType {
    const categories = classifyInputDataTypes({ inputType: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
      idAttribute: el.getAttribute('id') || '', autocomplete: el.getAttribute('autocomplete') || '',
      ariaLabel: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '' });
    for (const type of ['CVV', 'OTP', 'PASSWORD', 'PAYMENT_CARD', 'IDENTITY_DOCUMENT', 'EMAIL', 'PHONE', 'USERNAME']) {
      if (categories.includes(type as typeof categories[number])) return ({ PAYMENT_CARD: 'CARD', IDENTITY_DOCUMENT: 'ID' }[type] || type) as SensitiveType;
    }
    if (/\b(recovery|backup)[-_ ]?code\b/i.test(`${el.getAttribute('name') || ''} ${el.getAttribute('autocomplete') || ''}`)) return 'RECOVERY';
    return categories.length ? 'OTHER_SENSITIVE' : ['checkbox', 'radio', 'button', 'submit'].includes(el.getAttribute('type') || '') ? 'NON_SENSITIVE' : 'UNKNOWN';
  }
  const origin = () => safeOrigin(doc.location.href);
  function scan(mutated = false) {
    const events: Observation[] = [];
    if (mutated) events.push(observation({ event_type: 'DOM_MUTATION', frame_origin: origin() }));
    const purpose = inferPagePurpose(doc);
    if (purpose !== lastPurpose) {
      events.push(observation({ event_type: 'PAGE_CONTEXT_OBSERVED', frame_origin: origin(), page_purpose: purpose,
        purpose_source: purpose === 'UNKNOWN' ? 'UNKNOWN' : 'STATIC_SEMANTICS' }));
      lastPurpose = purpose;
    }
    for (const form of doc.querySelectorAll('form')) {
      const target = safeOrigin(form.action, doc.baseURI);
      if (!targets.has(form) || targets.get(form) !== target) {
        events.push(observation({ event_type: targets.has(form) ? 'FORM_TARGET_CHANGED' : 'FORM_DISCOVERED',
          form_id: id(form, 'f'), frame_origin: origin(), target_origin: target }));
        targets.set(form, target);
        events.push(observation({ event_type: 'FORM_TARGET_OBSERVED', form_id: id(form, 'f'), frame_origin: origin(), target_origin: target }));
      }
    }
    for (const input of doc.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('input,select,textarea')) {
      const type = category(input);
      const formId = input.form ? id(input.form, 'f') : null;
      const signature = `${type}:${formId}`;
      if (discovered.get(input) === signature) continue;
      discovered.set(input, signature);
      events.push(observation({ event_type: 'FIELD_DISCOVERED', field_id: id(input, 'e'), form_id: formId, frame_origin: origin(), sensitive_type: type }));
    }
    if (events.length) send(events);
  }
  function interaction(ev: Event) {
    const input = ev.target;
    if (!(input instanceof HTMLInputElement || input instanceof HTMLSelectElement || input instanceof HTMLTextAreaElement)) return;
    const type = category(input);
    if (['UNKNOWN', 'NON_SENSITIVE'].includes(type)) return;
    if (input.form && !interactedTargets.has(input.form)) interactedTargets.set(input.form, safeOrigin(input.form.action, doc.baseURI));
    send([observation({ event_type: 'SENSITIVE_INTERACTION', field_id: id(input, 'e'), form_id: input.form ? id(input.form, 'f') : null,
      frame_origin: origin(), sensitive_type: type, interaction_type: ev.type === 'focusin' ? 'focus' : 'input' })]);
  }
  return {
    scan,
    setAgentAction(action: 'ALLOW' | 'WARN' | 'CONFIRM') { agentRequiresConfirmation = action === 'CONFIRM'; },
    start() {
      send([observation({ event_type: 'DOCUMENT_STARTED', frame_origin: origin() })]); scan();
      doc.defaultView?.addEventListener('pagehide', () => send([observation({ event_type: 'DOCUMENT_ENDED', frame_origin: origin() })]));
      doc.addEventListener('focusin', interaction, true); doc.addEventListener('input', interaction, true);
      doc.addEventListener('submit', ev => {
        const form = ev.target;
        if (!(form instanceof HTMLFormElement)) return;
        const submitter = (ev as SubmitEvent).submitter;
        const target = submitter?.hasAttribute('formaction') && (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement)
          ? submitter.formAction : form.action;
        const targetOrigin = safeOrigin(target, doc.baseURI);
        // Synchronous guard closes the asynchronous worker round-trip race. No field value is accessed.
        // Capture cancellation is scoped to this submit event; form.submit(), fetch/XHR and hostile handlers may bypass it.
        const previous = interactedTargets.get(form);
        const hasSensitiveField = Array.from(form.elements).some(field => !['UNKNOWN', 'NON_SENSITIVE'].includes(category(field)));
        const status = destinationStatus(origin(), targetOrigin);
        const changed = previous && targetOrigin && targetOrigin !== previous && targetOrigin !== origin();
        const submitterMismatch = !!targetOrigin && targets.has(form) && targetOrigin !== targets.get(form);
        const needsReview = hasSensitiveField && (agentRequiresConfirmation || changed || submitterMismatch || status === 'HTTPS_DOWNGRADE');
        if (needsReview) {
          const reason = agentRequiresConfirmation ? 'The security assessment requires confirmation before sensitive submission.' : changed ? 'The destination changed after sensitive-field interaction.' : status === 'HTTPS_DOWNGRADE'
            ? 'This HTTPS page will submit to an unencrypted HTTP destination.' : 'The effective submission destination differs from the observed form destination.';
          const confirmed = doc.defaultView?.confirm(`CAPSTONE-1: ${reason}\nPage: ${origin() ?? 'unknown'}\nDestination: ${targetOrigin ?? 'unknown or unsupported'}\nThis is a verification request, not proof of phishing. Continue with this submission?`) === true;
          if (!confirmed) { ev.preventDefault(); ev.stopImmediatePropagation(); }
          send([observation({ event_type: confirmed ? 'SUBMISSION_CONFIRMED' : 'SUBMISSION_PREVENTED', form_id: id(form, 'f'), frame_origin: origin(), target_origin: targetOrigin })]);
        }
        send([observation({ event_type: 'FORM_SUBMISSION_ATTEMPT', form_id: id(form, 'f'), frame_origin: origin(),
          target_origin: safeOrigin(target, doc.baseURI), interaction_type: 'submit' })]);
      }, true);
    },
  };
}
