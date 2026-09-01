const fs = require('fs');
const path = require('path');

function varint(value) {
  const bytes = [];
  let v = value >>> 0;
  while (v >= 0x80) {
    bytes.push((v & 0x7f) | 0x80);
    v = (v >>> 7);
  }
  bytes.push(v);
  return Buffer.from(bytes);
}

function field(tag, wireType, payload) {
  return Buffer.concat([varint((tag << 3) | wireType), varint(payload.length), payload]);
}

function fieldVarint(tag, value) {
  return field(tag, 0, varint(value));
}

function fieldString(tag, value) {
  return field(tag, 2, Buffer.from(value, 'utf8'));
}

function fieldFloat(tag, value) {
  const b = Buffer.alloc(4);
  b.writeFloatLE(value, 0);
  return field(tag, 5, b);
}

function fieldFloatPacked(tag, values) {
  const packed = Buffer.alloc(values.length * 4);
  values.forEach((value, index) => packed.writeFloatLE(value, index * 4));
  return field(tag, 2, packed);
}

function message(fields) {
  return Buffer.concat(fields);
}

function dimensionMessage(value) {
  return message([
    fieldVarint(1, value)
  ]);
}

function tensorShapeMessage(dimValues) {
  return message(dimValues.map((dim) => field(1, 2, dimensionMessage(dim))));
}

function tensorTypeMessage(dimValues) {
  return message([
    fieldVarint(1, 1),
    field(2, 2, tensorShapeMessage(dimValues))
  ]);
}

function valueInfoMessage(name, dimValues) {
  return message([
    fieldString(1, name),
    field(2, 2, tensorTypeMessage(dimValues))
  ]);
}

function tensorMessage(name, dims, values) {
  return message([
    fieldString(1, name),
    ...dims.map((d) => fieldVarint(2, d)),
    fieldVarint(3, 1),
    fieldFloatPacked(6, values)
  ]);
}

function nodeMessage() {
  const inputNames = ['X', 'W'];
  const outputNames = ['Y'];
  return message([
    ...inputNames.map((n) => fieldString(1, n)),
    ...outputNames.map((n) => fieldString(2, n)),
    fieldString(3, 'MatMul'),
    fieldString(4, 'MatMul')
  ]);
}

function graphMessage() {
  const inputInfo = valueInfoMessage('X', [1, 5]);
  const outputInfo = valueInfoMessage('Y', [1, 1]);
  const weight = tensorMessage('W', [5, 1], [0.4, 0.3, 0.3, 0.0, 0.0]);
  const node = nodeMessage();

  return message([
    field(1, 2, node),
    fieldString(2, 'capstone_toy_model'),
    field(5, 2, weight),
    field(11, 2, inputInfo),
    field(12, 2, outputInfo)
  ]);
}

function opsetMessage() {
  return message([
    fieldString(1, ''),
    fieldVarint(2, 13)
  ]);
}

function modelMessage() {
  return message([
    fieldVarint(1, 8),
    fieldString(2, 'capstone-1'),
    fieldString(3, '1.1.0'),
    field(7, 2, graphMessage()),
    field(8, 2, opsetMessage())
  ]);
}

const outDir = path.resolve(__dirname, '../browser-extension/assets');
const fixtureDir = path.resolve(__dirname, '../tests/fixtures');
fs.mkdirSync(outDir, { recursive: true });
fs.mkdirSync(fixtureDir, { recursive: true });

const modelBytes = modelMessage();
fs.writeFileSync(path.join(outDir, 'model.onnx'), modelBytes);
fs.writeFileSync(path.join(fixtureDir, 'model.onnx'), modelBytes);

console.log('Wrote', path.join(outDir, 'model.onnx'));
console.log('Wrote', path.join(fixtureDir, 'model.onnx'));
