// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { DynamicDOMObserver } from '../../browser-extension/src/content/observer';
import { createTypedEvents } from '../../browser-extension/src/content/typed-events';
import type { Observation } from '../../browser-extension/src/core/tsfeg';

function resetDocument() {
  document.head.innerHTML = '';
  document.body.innerHTML = '';
}

afterEach(() => {
  resetDocument();
});

describe('open Shadow DOM structural collection', () => {
  it('discovers a sensitive field inside a reachable open shadow root without reading its value', () => {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = '<form action="https://sink.test"><input type="password"></form>';

    const input = root.querySelector('input')!;
    Object.defineProperty(input, 'value', {
      get() {
        throw new Error('Forbidden value read');
      },
    });

    document.body.append(host);

    const events: Observation[] = [];
    createTypedEvents(document, batch => events.push(...batch)).scan();

    expect(events.filter(event =>
      event.event_type === 'FIELD_DISCOVERED' &&
      event.sensitive_type === 'PASSWORD'
    )).toHaveLength(1);

    expect(events.some(event =>
      event.event_type === 'FORM_TARGET_OBSERVED' &&
      event.target_origin === 'https://sink.test'
    )).toBe(true);

    expect(JSON.stringify(events)).not.toContain('Forbidden value read');
  });

  it('does not claim visibility into closed shadow roots', () => {
    const host = document.createElement('div');
    const closed = host.attachShadow({ mode: 'closed' });
    closed.innerHTML = '<input type="password">';
    document.body.append(host);

    const events: Observation[] = [];
    createTypedEvents(document, batch => events.push(...batch)).scan();

    expect(events.some(event =>
      event.event_type === 'FIELD_DISCOVERED' &&
      event.sensitive_type === 'PASSWORD'
    )).toBe(false);

    expect(host.shadowRoot).toBeNull();
  });

  it('registers an open shadow root inserted after observation starts', async () => {
    const events: Observation[] = [];
    const typed = createTypedEvents(document, batch => events.push(...batch));
    const observer = new DynamicDOMObserver(() => typed.scan(true), 0, document);

    typed.scan();
    observer.start();

    try {
      const host = document.createElement('section');
      const root = host.attachShadow({ mode: 'open' });
      root.innerHTML = '<input autocomplete="one-time-code">';
      document.body.append(host);

      await new Promise(resolve => setTimeout(resolve, 0));

      expect(events.some(event =>
        event.event_type === 'FIELD_DISCOVERED' &&
        event.sensitive_type === 'OTP'
      )).toBe(true);
    } finally {
      observer.stop();
    }
  });

  it('captures sensitive interaction inside an open shadow root once', () => {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = '<input type="password">';
    document.body.append(host);

    const events: Observation[] = [];
    const typed = createTypedEvents(document, batch => events.push(...batch));
    typed.start();

    const input = root.querySelector('input')!;
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));

    expect(events.filter(event =>
      event.event_type === 'SENSITIVE_INTERACTION' &&
      event.sensitive_type === 'PASSWORD'
    )).toHaveLength(1);
  });
});
