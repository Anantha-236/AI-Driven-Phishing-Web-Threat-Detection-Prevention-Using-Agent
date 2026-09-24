import { readFile } from 'node:fs/promises';
import * as ort from 'onnxruntime-web/wasm';

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`Missing ${name}`);
  return process.argv[index + 1];
}

const manifestPath = arg('--manifest');
const modelPath = arg('--model');
const parityPath = arg('--parity');

const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const parity = JSON.parse(await readFile(parityPath, 'utf8'));
const model = await readFile(modelPath);

if (manifest.schema_version !== 'stage-b-release-candidate-1' || manifest.status !== 'PASS') {
  throw new Error('Invalid Stage B release manifest');
}
if (manifest.release_gate?.deploy !== false || manifest.release_gate?.autonomous_blocking !== false) {
  throw new Error('Task 12 accepts only a non-deploying Stage B candidate');
}
if (manifest.parity?.test_partition_used !== false || parity.test_partition_used !== false) {
  throw new Error('WASM parity must not reuse the locked final-test partition');
}
if (JSON.stringify(manifest.feature_names) !== JSON.stringify(parity.feature_names)) {
  throw new Error('Manifest/parity feature order mismatch');
}

ort.env.wasm.numThreads = 1;
ort.env.wasm.proxy = false;

const session = await ort.InferenceSession.create(model, {
  executionProviders: ['wasm'],
  graphOptimizationLevel: 'all',
});

if (session.inputNames.length !== 1 || session.inputNames[0] !== manifest.onnx.input_name) {
  throw new Error('WASM input contract differs from frozen manifest');
}
if (!session.outputNames.includes(manifest.onnx.probability_output_name)) {
  throw new Error('WASM probability output differs from frozen manifest');
}

let maximumError = 0;
for (const row of parity.vectors) {
  if (!Array.isArray(row.feature_vector) || row.feature_vector.length !== manifest.feature_names.length) {
    throw new Error(`Invalid feature vector for ${row.sample_id}`);
  }
  const input = new ort.Tensor(
    'float32',
    Float32Array.from(row.feature_vector),
    [1, row.feature_vector.length],
  );
  const outputs = await session.run({ [manifest.onnx.input_name]: input });
  const probability = outputs[manifest.onnx.probability_output_name];

  if (!probability ||
      probability.dims.length !== 2 ||
      probability.dims[0] !== 1 ||
      probability.dims[1] !== 2) {
    throw new Error(`Invalid WASM probability tensor for ${row.sample_id}`);
  }

  const score = Number(probability.data[manifest.onnx.positive_class_index]);
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new Error(`Invalid WASM probability for ${row.sample_id}`);
  }
  const error = Math.abs(score - Number(row.expected_calibrated_probability));
  maximumError = Math.max(maximumError, error);
}

if (maximumError > Number(manifest.parity.tolerance)) {
  throw new Error(`onnxruntime-web WASM parity failed: ${maximumError} > ${manifest.parity.tolerance}`);
}

console.log(JSON.stringify({
  status: 'PASS',
  runtime: 'onnxruntime-web/wasm',
  vectors: parity.vectors.length,
  maximum_absolute_probability_error: maximumError,
  tolerance: manifest.parity.tolerance,
  test_partition_used: false,
}, null, 2));
