import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

test('safe controlled collector produces Task-5-compatible privacy-safe episodes', async () => {
  test.setTimeout(90000);
  const runtime = resolve('.runtime/stage-b-acquisition-smoke');
  mkdirSync(runtime, { recursive: true });
  const splitsPath = resolve(runtime, 'splits.json');
  const planPath = resolve(runtime, 'plan.json');
  const episodesPath = resolve(runtime, 'episodes.json');
  const featuresPath = resolve(runtime, 'features.json');

  const partitionNames = ['train', 'selection', 'calibration', 'test'] as const;
  const partitions = Object.fromEntries(partitionNames.map((partition, index) => [partition, {
    records: [{
      sample_id: `acq-${partition}`,
      ground_truth: index % 2,
      artifact_group: `artifact-${partition}`,
      domain_group: `domain-${partition}.example`,
      brand_group: `brand-${partition}`,
      source_groups: [`source-${partition}`],
      observed_at: `2026-09-${20 + index}T12:00:00Z`,
    }],
  }]));
  writeFileSync(splitsPath, JSON.stringify({ schema_version: 'stage-b-splits-1', partitions }, null, 2));

  const items = partitionNames.map(partition => ({
    sample_id: `acq-${partition}`,
    mode: 'CONTROLLED_LOCAL',
    target_url: 'http://127.0.0.1:41731/suspicious',
    collection_provenance: 'CONTROLLED_BROWSER',
    wait_ms: 500,
  }));
  writeFileSync(planPath, JSON.stringify({
    schema_version: 'stage-b-acquisition-plan-1',
    plan_id: 'browser-smoke',
    created_at: '2026-09-24T17:00:00Z',
    items,
  }, null, 2));

  execFileSync('node', [
    'scripts/stage-b-collect-episodes.mjs',
    '--plan', planPath,
    '--splits', splitsPath,
    '--output', episodesPath,
    '--headless', 'true',
  ], { cwd: process.cwd(), encoding: 'utf8', windowsHide: true, timeout: 60000 });

  const episodes = JSON.parse(readFileSync(episodesPath, 'utf8'));
  expect(episodes.schema_version).toBe('stage-b-event-episodes-1');
  expect(episodes.failures).toEqual([]);
  expect(episodes.episodes).toHaveLength(4);

  const containsExactKey = (value: unknown, forbiddenKey: string): boolean => {
    if (Array.isArray(value)) {
      return value.some(item => containsExactKey(item, forbiddenKey));
    }
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(record, forbiddenKey)) return true;
      return Object.values(record).some(item => containsExactKey(item, forbiddenKey));
    }
    return false;
  };

  expect(containsExactKey(episodes, 'target_url')).toBe(false);
  expect(episodes.safety_policy?.target_urls_persisted).toBe(false);

  for (const episode of episodes.episodes) {
    expect(episode.collection_provenance).toBe('CONTROLLED_BROWSER');
    expect(episode.dropped_events).toBe(0);
    expect(episode.events.length).toBeGreaterThan(0);
    expect(episode.events_sha256).toMatch(/^[0-9a-f]{64}$/);
  }

  execFileSync('python', [
    '-m', 'ml.data.materialize_stage_b_features',
    '--splits', splitsPath,
    '--episodes', episodesPath,
    '--output', featuresPath,
  ], { cwd: process.cwd(), encoding: 'utf8', windowsHide: true, timeout: 30000 });

  const features = JSON.parse(readFileSync(featuresPath, 'utf8'));
  expect(features.schema_version).toBe('stage-b-feature-dataset-1');
  expect(features.feature_version).toBe('context-features-1');
  for (const partition of partitionNames) {
    expect(features.partitions[partition].sample_count).toBe(1);
    expect(features.partitions[partition].records[0].feature_vector.length)
      .toBe(features.feature_names.length);
  }
});
