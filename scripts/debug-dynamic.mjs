import { chromium } from '@playwright/test';
import path from 'node:path';

const dist = path.resolve(process.cwd(), 'dist');
const browser = await chromium.launch({
  headless: false,
  args: [
    `--disable-extensions-except=${dist}`,
    `--load-extension=${dist}`,
    '--no-sandbox',
  ],
});

const page = await browser.newPage();
page.on('console', (msg) => console.log('PAGE-CONSOLE', msg.type(), msg.text()));
page.on('pageerror', (err) => console.log('PAGE-ERROR', err.message));

await page.goto('http://127.0.0.1:41731/dynamic', { waitUntil: 'domcontentloaded' });

const initial = await page.evaluate(() => ({
  readyState: document.readyState,
  formCount: document.querySelectorAll('form').length,
  inputCount: document.querySelectorAll('input').length,
  featureMeta: document.documentElement.getAttribute('data-capstone-feature-meta'),
  evidenceMeta: document.documentElement.getAttribute('data-capstone-evidence-meta'),
  bodyChildren: document.body ? document.body.children.length : 0,
}));
console.log('INITIAL', JSON.stringify(initial));

await page.waitForFunction(() => {
  const featureMeta = document.documentElement.getAttribute('data-capstone-feature-meta');
  if (!featureMeta) return false;
  try {
    const features = JSON.parse(featureMeta);
    return features.form_count >= 1 && features.input_count >= 3;
  } catch {
    return false;
  }
}, { timeout: 30000 });

const final = await page.evaluate(() => ({
  readyState: document.readyState,
  formCount: document.querySelectorAll('form').length,
  inputCount: document.querySelectorAll('input').length,
  featureMeta: document.documentElement.getAttribute('data-capstone-feature-meta'),
  evidenceMeta: document.documentElement.getAttribute('data-capstone-evidence-meta'),
  inputs: Array.from(document.querySelectorAll('input')).map((input) => ({
    type: input.getAttribute('type'),
    name: input.getAttribute('name'),
    autocomplete: input.getAttribute('autocomplete'),
  })),
}));
console.log('FINAL', JSON.stringify(final));

await page.waitForTimeout(2000);
await browser.close();
