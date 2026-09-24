import { readFile } from 'node:fs/promises';
import * as ort from 'onnxruntime-node';

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
if (manifest.schema_version !== 'stage-b-release-candidate-1' || manifest.status !== 'PASS') {
  throw new Error('Invalid Stage B release manifest');
}
if (manifest.parity?.test_partition_used !== false || parity.test_partition_used !== false) {
  throw new Error('Parity must not use the final-test partition');
}
if (JSON.stringify(manifest.feature_names) !== JSON.stringify(parity.feature_names)) {
  throw new Error('Feature ordering differs between manifest and parity vectors');
}

const session = await ort.InferenceSession.create(modelPath);
if (session.inputNames.length !== 1 || session.inputNames[0] !== manifest.onnx.input_name) {
  throw new Error('ONNX input name differs from frozen manifest');
}
if (!session.outputNames.includes(manifest.onnx.probability_output_name)) {
  throw new Error('ONNX probability output differs from frozen manifest');
}

let maximumError = 0;
for (const row of parity.vectors) {
  if (!Array.isArray(row.feature_vector) || row.feature_vector.length !== manifest.feature_names.length) {
    throw new Error(`Invalid feature vector for ${row.sample_id}`);
  }
  const input = new ort.Tensor('float32', Float32Array.from(row.feature_vector), [1, row.feature_vector.length]);
  const outputs = await session.run({ [manifest.onnx.input_name]: input });
  const probability = outputs[manifest.onnx.probability_output_name];
  if (!probability || probability.dims.length !== 2 || probability.dims[0] !== 1 || probability.dims[1] !== 2) {
    throw new Error(`Invalid probability tensor for ${row.sample_id}`);
  }
  const score = Number(probability.data[manifest.onnx.positive_class_index]);
  const error = Math.abs(score - Number(row.expected_calibrated_probability));
  maximumError = Math.max(maximumError, error);
}
if (maximumError > Number(manifest.parity.tolerance)) {
  throw new Error(`Node ONNX parity failed: ${maximumError} > ${manifest.parity.tolerance}`);
}
console.log(JSON.stringify({
  status: 'PASS',
  vectors: parity.vectors.length,
  maximum_absolute_probability_error: maximumError,
  tolerance: manifest.parity.tolerance,
  runtime: 'onnxruntime-node',
}, null, 2));
