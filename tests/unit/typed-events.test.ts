// @vitest-environment jsdom
import { expect, it, vi } from 'vitest';
import { DynamicDOMObserver } from '../../browser-extension/src/content/observer';
import { createTypedEvents, inferPagePurpose } from '../../browser-extension/src/content/typed-events';
import { Observation } from '../../browser-extension/src/core/tsfeg';
import { DOMContentCollector } from '../../browser-extension/src/content/collector';
import { assessThreat } from '../../browser-extension/src/core/assessment';
import { extractFeatureVector } from '../../browser-extension/src/features/extractor';

it('emits only purpose categories and ignores editable and raw form text', () => {
  document.head.innerHTML = '<title>Sign in</title>';
  document.body.innerHTML = '<h1 contenteditable>Payment SECRET_SENTINEL</h1><form><textarea>Payment SECRET_SENTINEL</textarea><input type="password"></form>';
  for (const input of document.querySelectorAll('input,textarea')) {
    Object.defineProperty(input, 'value', { get() { throw new Error('Forbidden value read'); } });
    Object.defineProperty(input, 'textContent', { get() { throw new Error('Forbidden text read'); } });
  }
  const events: Observation[] = [];
  createTypedEvents(document, batch => events.push(...batch)).scan();
  expect(inferPagePurpose(document)).toBe('LOGIN');
  expect(events.find(e => e.event_type === 'PAGE_CONTEXT_OBSERVED')).toMatchObject({page_purpose:'LOGIN', purpose_source:'STATIC_SEMANTICS'});
  expect(JSON.stringify(events)).not.toMatch(/SECRET_SENTINEL|Sign in/);
  document.head.innerHTML = '<title>Sign in or create account</title>';
  expect(inferPagePurpose(document)).toBe('UNKNOWN');
});

it('does not demand confirmation solely for a stable unknown cross-origin login target', () => {
  document.head.innerHTML = '<title>Sign in</title>';
  document.body.innerHTML = '<form action="https://sso.new-service.test"><input type="password"><input autocomplete="one-time-code"></form>';
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const events: Observation[] = [];
  createTypedEvents(document, batch => events.push(...batch)).start();
  const attempt = new SubmitEvent('submit', { bubbles: true, cancelable: true });
  document.querySelector('form')!.dispatchEvent(attempt);
  expect(attempt.defaultPrevented).toBe(false);
  expect(confirm).not.toHaveBeenCalled();
  expect(events.some(e => e.event_type === 'FORM_SUBMISSION_ATTEMPT')).toBe(true);
  expect(events.some(e => e.event_type === 'SUBMISSION_PREVENTED')).toBe(false);
  confirm.mockRestore();
});

it('does not let the compatibility model call ordinary password and OTP inputs malicious', () => {
  document.head.innerHTML = '';
  document.body.innerHTML = '<form action="https://example.test/login"><input type="password"><input autocomplete="one-time-code"></form>';
  const evidence = DOMContentCollector.collectFromDocument(document, 'https://example.test');
  const threat = assessThreat({ evidence, features: extractFeatureVector(evidence),
    modelResult: { rawScore: 0.99, inferenceLatencyMs: 1, runtimeUsed: 'service-worker', modelId: 'prototype' } });
  expect(threat.threatLevel).toBe('insufficient_evidence');
});

it('rechecks a submitter override before transmission and cancels an unverified sensitive destination without reading values', () => {
  document.head.innerHTML = '';
  document.body.innerHTML = '<form><input type="password"><button type="submit" formaction="https://unverified.test/sink">Submit</button></form>';
  const events: Observation[] = [];
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  // jsdom does not implement HTMLButtonElement.formAction; the browser suite
  // separately exercises the real native submitter override.
  Object.defineProperty(document.querySelector('button'), 'formAction', { value: 'https://unverified.test/sink' });
  Object.defineProperty(document.querySelector('input'), 'value', { get() { throw new Error('Forbidden read'); } });
  createTypedEvents(document, batch => events.push(...batch)).start();
  const event = new SubmitEvent('submit', { bubbles: true, cancelable: true, submitter: document.querySelector('button')! });
  document.querySelector('form')!.dispatchEvent(event);
  expect(event.defaultPrevented).toBe(true);
  expect(confirm).toHaveBeenCalledWith(expect.stringContaining('https://unverified.test'));
  expect(events.some(e => e.event_type === 'SUBMISSION_PREVENTED' && e.target_origin === 'https://unverified.test')).toBe(true);
  confirm.mockRestore();
});

it('retains fields and effective destinations across base changes and body replacement without reading values', async () => {
  document.head.innerHTML = '<base href="https://first.test/">';
  document.body.innerHTML = '<form action="/sink"><input type="password"></form>';
  const input = document.querySelector('input')!;
  Object.defineProperty(input, 'value', { get() { throw new Error('Raw value read'); } });
  const events: Observation[] = [];
  const typed = createTypedEvents(document, batch => events.push(...batch));
  const observer = new DynamicDOMObserver(() => typed.scan(true), 0, document);
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));
  typed.scan(); observer.start();
  try {
    expect(events.some(e => e.target_origin === 'https://first.test')).toBe(true);
    document.querySelector('base')!.href = 'https://second.test/';
    await settle();
    expect(events.some(e => e.target_origin === 'https://second.test')).toBe(true);
    const body = document.createElement('body');
    body.innerHTML = '<input autocomplete="one-time-code">';
    document.body.replaceWith(body);
    await settle();
    expect(events.filter(e => e.event_type === 'FIELD_DISCOVERED' && e.sensitive_type === 'OTP')).toHaveLength(1);
    expect(events.every(e => !('value' in e))).toBe(true);
  } finally { observer.stop(); }
});

it('never reads password, OTP, card, CVV, recovery or raw form values during collection', () => {
  document.body.innerHTML = '<form><input type="password"><input autocomplete="one-time-code"><input autocomplete="cc-number"><input autocomplete="cc-csc"><input name="recovery-code"><textarea></textarea><select><option>dummy</option></select></form>';
  const events: Observation[] = [];
  for (const field of document.querySelectorAll('input,textarea,select')) {
    Object.defineProperty(field, 'value', { get() { throw new Error('Forbidden value getter'); } });
    Object.defineProperty(field, 'textContent', { get() { throw new Error('Forbidden content getter'); } });
  }
  createTypedEvents(document, batch => events.push(...batch)).scan();
  const snapshot = DOMContentCollector.collectFromDocument(document, 'https://example.test/?token=PRIVACY_SENTINEL');
  expect(JSON.stringify({ events, snapshot })).not.toContain('PRIVACY_SENTINEL');
  expect(events.filter(e => e.event_type === 'FIELD_DISCOVERED')).toHaveLength(7);
});
