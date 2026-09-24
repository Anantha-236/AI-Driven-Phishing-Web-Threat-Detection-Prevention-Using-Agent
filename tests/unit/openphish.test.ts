import { describe, expect, it } from 'vitest';
import {
  compilePhishingRules,
  OPENPHISH_RULE_LIMIT,
  OPENPHISH_RULE_START,
} from '../../browser-extension/src/core/reputation/openphish';

describe('OpenPhish provider rule compiler', () => {
  it('keeps exact query-free http(s) indicators and preserves exact matching', () => {
    const result = compilePhishingRules([
      'https://phish.example/login',
      'http://other.example/path',
    ].join('\n'));

    expect(result.excluded).toBe(0);
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0]).toMatchObject({
      id: OPENPHISH_RULE_START,
      action: { type: 'block' },
      condition: {
        urlFilter: '|https://phish.example/login|',
        isUrlFilterCaseSensitive: true,
      },
    });
  });

  it('excludes query-bearing, credential, wildcard, malformed and IP-only indicators', () => {
    const result = compilePhishingRules([
      'https://example.test/path?token=secret',
      'https://user:password@example.test/path',
      'https://*.example.test/path',
      'not-a-url',
      'https://192.0.2.1/path',
      'https://valid.example/path',
    ].join('\n'));

    expect(result.rules).toHaveLength(1);
    expect(result.excluded).toBe(5);
    expect(result.rules[0].condition.urlFilter).toBe('|https://valid.example/path|');
  });

  it('deduplicates indicators without consuming rule capacity twice', () => {
    const result = compilePhishingRules([
      'https://same.example/path',
      'https://same.example/path',
    ].join('\n'));

    expect(result.rules).toHaveLength(1);
    expect(result.excluded).toBe(0);
  });

  it('caps external feed rules to the reserved OpenPhish range', () => {
    const indicators = Array.from(
      { length: OPENPHISH_RULE_LIMIT + 2 },
      (_, index) => `https://feed-${index}.example/path`,
    );

    const result = compilePhishingRules(indicators.join('\n'));

    expect(result.rules).toHaveLength(OPENPHISH_RULE_LIMIT);
    expect(result.excluded).toBe(2);
    expect(result.rules.at(-1)?.id).toBe(
      OPENPHISH_RULE_START + OPENPHISH_RULE_LIMIT - 1,
    );
  });
});
