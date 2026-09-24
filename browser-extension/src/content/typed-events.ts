// M1 DOM event semantics adapted to the existing CAPSTONE collector/observer.
// This module creates no observer and never reads field values.
import { classifyInputDataTypes } from '../core/evidence/data-type-classifier';
import { observation, Observation, safeOrigin, SensitiveType } from '../core/tsfeg';
import { destinationStatus } from '../core/profiles/service-profiles';
import { collectOpenRoots, queryAcrossOpenRoots, type ObservableRoot } from './shadow-roots';

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

type FormControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

function associatedForm(control: FormControl): HTMLFormElement | null {
  if (control.form) return control.form;
  const nearest = control.closest('form');
  return nearest instanceof HTMLFormElement ? nearest : null;
}

export function createTypedEvents(doc: Document, send: (events: Observation[]) => void) {
  let agentRequiresConfirmation = false;
  let started = false;
  const ids = new WeakMap<Element, string>();
  const discovered = new WeakMap<Element, string>();
  const targets = new WeakMap<HTMLFormElement, string | null>();
  const interactedTargets = new WeakMap<HTMLFormElement, string | null>();
  const listenerRoots = new WeakSet<ObservableRoot>();
  const directlyBoundControls = new WeakSet<FormControl>();
  const directlyBoundForms = new WeakSet<HTMLFormElement>();
  const handledInteractionEvents = new WeakSet<Event>();
  const handledSubmitEvents = new WeakSet<Event>();
  let nextId = 0;
  let lastPurpose: Observation['page_purpose'] | undefined;

  function id(el: Element, prefix: string) {
    if (!ids.has(el)) ids.set(el, `${prefix}-${++nextId}`);
    return ids.get(el)!;
  }

  function category(el: Element): SensitiveType {
    const categories = classifyInputDataTypes({
      inputType: el.getAttribute('type') || '',
      name: el.getAttribute('name') || '',
      idAttribute: el.getAttribute('id') || '',
      autocomplete: el.getAttribute('autocomplete') || '',
      ariaLabel: el.getAttribute('aria-label') || '',
      placeholder: el.getAttribute('placeholder') || '',
    });
    for (const type of ['CVV', 'OTP', 'PASSWORD', 'PAYMENT_CARD', 'IDENTITY_DOCUMENT', 'EMAIL', 'PHONE', 'USERNAME']) {
      if (categories.includes(type as typeof categories[number])) {
        return ({ PAYMENT_CARD: 'CARD', IDENTITY_DOCUMENT: 'ID' }[type] || type) as SensitiveType;
      }
    }
    if (/\b(recovery|backup)[-_ ]?code\b/i.test(`${el.getAttribute('name') || ''} ${el.getAttribute('autocomplete') || ''}`)) return 'RECOVERY';
    return categories.length
      ? 'OTHER_SENSITIVE'
      : ['checkbox', 'radio', 'button', 'submit'].includes(el.getAttribute('type') || '')
        ? 'NON_SENSITIVE'
        : 'UNKNOWN';
  }

  const origin = () => safeOrigin(doc.location.href);

  function isControl(target: EventTarget | null): target is FormControl {
    return target instanceof HTMLInputElement ||
      target instanceof HTMLSelectElement ||
      target instanceof HTMLTextAreaElement;
  }

  function eventControl(event: Event): FormControl | null {
    if (isControl(event.target)) return event.target;
    for (const candidate of event.composedPath()) {
      if (isControl(candidate)) return candidate;
    }
    return null;
  }

  function eventForm(event: Event): HTMLFormElement | null {
    if (event.target instanceof HTMLFormElement) return event.target;
    for (const candidate of event.composedPath()) {
      if (candidate instanceof HTMLFormElement) return candidate;
    }
    return null;
  }

  function interaction(event: Event) {
    const input = eventControl(event);
    if (!input || handledInteractionEvents.has(event)) return;
    handledInteractionEvents.add(event);

    const type = category(input);
    if (['UNKNOWN', 'NON_SENSITIVE'].includes(type)) return;

    const form = associatedForm(input);
    if (form && !interactedTargets.has(form)) {
      interactedTargets.set(form, safeOrigin(form.action, doc.baseURI));
    }

    send([observation({
      event_type: 'SENSITIVE_INTERACTION',
      field_id: id(input, 'e'),
      form_id: form ? id(form, 'f') : null,
      frame_origin: origin(),
      sensitive_type: type,
      interaction_type: event.type === 'focusin' ? 'focus' : 'input',
    })]);
  }

  function submit(event: Event) {
    const form = eventForm(event);
    if (!form || handledSubmitEvents.has(event)) return;
    handledSubmitEvents.add(event);

    const submitEvent = event as SubmitEvent;
    const submitter = submitEvent.submitter;
    const target = submitter?.hasAttribute('formaction') &&
      (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement)
        ? submitter.formAction
        : form.action;
    const targetOrigin = safeOrigin(target, doc.baseURI);

    // Synchronous guard closes the asynchronous worker round-trip race. No field value is accessed.
    // Capture cancellation is scoped to this submit event; form.submit(), fetch/XHR and hostile handlers may bypass it.
    const previous = interactedTargets.get(form);
    const hasSensitiveField = Array.from(form.elements).some(field =>
      !['UNKNOWN', 'NON_SENSITIVE'].includes(category(field))
    );
    const status = destinationStatus(origin(), targetOrigin);
    const changed = !!previous && !!targetOrigin && targetOrigin !== previous && targetOrigin !== origin();
    const submitterMismatch = !!targetOrigin && targets.has(form) && targetOrigin !== targets.get(form);
    const needsReview = hasSensitiveField &&
      (agentRequiresConfirmation || changed || submitterMismatch || status === 'HTTPS_DOWNGRADE');

    if (needsReview) {
      const reason = agentRequiresConfirmation
        ? 'The security assessment requires confirmation before sensitive submission.'
        : changed
          ? 'The destination changed after sensitive-field interaction.'
          : status === 'HTTPS_DOWNGRADE'
            ? 'This HTTPS page will submit to an unencrypted HTTP destination.'
            : 'The effective submission destination differs from the observed form destination.';
      const confirmed = doc.defaultView?.confirm(
        `CAPSTONE-1: ${reason}\nPage: ${origin() ?? 'unknown'}\nDestination: ${targetOrigin ?? 'unknown or unsupported'}\nThis is a verification request, not proof of phishing. Continue with this submission?`
      ) === true;
      if (!confirmed) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
      send([observation({
        event_type: confirmed ? 'SUBMISSION_CONFIRMED' : 'SUBMISSION_PREVENTED',
        form_id: id(form, 'f'),
        frame_origin: origin(),
        target_origin: targetOrigin,
      })]);
    }

    send([observation({
      event_type: 'FORM_SUBMISSION_ATTEMPT',
      form_id: id(form, 'f'),
      frame_origin: origin(),
      target_origin: safeOrigin(target, doc.baseURI),
      interaction_type: 'submit',
    })]);
  }

  function attachListenersToReachableRoots(): void {
    if (!started) return;
    for (const root of collectOpenRoots(doc)) {
      if (listenerRoots.has(root)) continue;
      root.addEventListener('focusin', interaction, true);
      root.addEventListener('input', interaction, true);
      root.addEventListener('submit', submit, true);
      listenerRoots.add(root);
    }
  }

  function bindControlDirectly(control: FormControl): void {
    if (!started || directlyBoundControls.has(control)) return;
    control.addEventListener('focusin', interaction, true);
    control.addEventListener('input', interaction, true);
    directlyBoundControls.add(control);
  }

  function bindFormDirectly(form: HTMLFormElement): void {
    if (!started || directlyBoundForms.has(form)) return;
    form.addEventListener('submit', submit, true);
    directlyBoundForms.add(form);
  }

  function scan(mutated = false) {
    attachListenersToReachableRoots();
    const events: Observation[] = [];
    if (mutated) events.push(observation({ event_type: 'DOM_MUTATION', frame_origin: origin() }));

    const purpose = inferPagePurpose(doc);
    if (purpose !== lastPurpose) {
      events.push(observation({
        event_type: 'PAGE_CONTEXT_OBSERVED',
        frame_origin: origin(),
        page_purpose: purpose,
        purpose_source: purpose === 'UNKNOWN' ? 'UNKNOWN' : 'STATIC_SEMANTICS',
      }));
      lastPurpose = purpose;
    }

    for (const form of queryAcrossOpenRoots<HTMLFormElement>(doc, 'form')) {
      bindFormDirectly(form);
      const target = safeOrigin(form.action, doc.baseURI);
      if (!targets.has(form) || targets.get(form) !== target) {
        events.push(observation({
          event_type: targets.has(form) ? 'FORM_TARGET_CHANGED' : 'FORM_DISCOVERED',
          form_id: id(form, 'f'),
          frame_origin: origin(),
          target_origin: target,
        }));
        targets.set(form, target);
        events.push(observation({
          event_type: 'FORM_TARGET_OBSERVED',
          form_id: id(form, 'f'),
          frame_origin: origin(),
          target_origin: target,
        }));
      }
    }

    for (const input of queryAcrossOpenRoots<FormControl>(doc, 'input,select,textarea')) {
      bindControlDirectly(input);
      const type = category(input);
      const form = associatedForm(input);
      const formId = form ? id(form, 'f') : null;
      const signature = `${type}:${formId}`;
      if (discovered.get(input) === signature) continue;
      discovered.set(input, signature);
      events.push(observation({
        event_type: 'FIELD_DISCOVERED',
        field_id: id(input, 'e'),
        form_id: formId,
        frame_origin: origin(),
        sensitive_type: type,
      }));
    }

    if (events.length) send(events);
  }

  return {
    scan,
    setAgentAction(action: 'ALLOW' | 'WARN' | 'CONFIRM') {
      agentRequiresConfirmation = action === 'CONFIRM';
    },
    start() {
      if (started) return;
      started = true;
      attachListenersToReachableRoots();
      send([observation({ event_type: 'DOCUMENT_STARTED', frame_origin: origin() })]);
      scan();
      doc.defaultView?.addEventListener('pagehide', () =>
        send([observation({ event_type: 'DOCUMENT_ENDED', frame_origin: origin() })])
      );
    },
  };
}
