// Apple binary property list (bplist00) reader and writer.
// Only the types the Photographic Styles plist uses are handled: dict, string,
// bool, int, real, data. That is the whole schema observed in native files.

import { u, be, concat } from "./box.js";

export function parseBplist(d) {
  if (String.fromCharCode(...d.subarray(0, 6)) !== "bplist")
    throw new Error("Not a binary plist");
  const trailer = d.length - 32;
  const offsetSize = d[trailer + 6];
  const refSize = d[trailer + 7];
  const numObjects = u(d, trailer + 8, 8);
  const topObject = u(d, trailer + 16, 8);
  const offsetTableStart = u(d, trailer + 24, 8);
  const offsets = [];
  for (let i = 0; i < numObjects; i++)
    offsets.push(u(d, offsetTableStart + i * offsetSize, offsetSize));

  const view = new DataView(d.buffer, d.byteOffset, d.byteLength);

  function readSized(p) {
    // Returns [count, positionAfterCount] for the "0xF" extended-length form.
    const marker = d[p];
    let count = marker & 0x0f;
    p += 1;
    if (count === 0x0f) {
      const intMarker = d[p];
      const nbytes = 1 << (intMarker & 0x0f);
      count = u(d, p + 1, nbytes);
      p += 1 + nbytes;
    }
    return [count, p];
  }

  function readObject(index) {
    let p = offsets[index];
    const marker = d[p];
    const hi = marker & 0xf0;
    const lo = marker & 0x0f;
    switch (hi) {
      case 0x00:
        if (lo === 0) return null;
        if (lo === 8) return false;
        if (lo === 9) return true;
        throw new Error(`Unsupported primitive 0x${marker.toString(16)}`);
      case 0x10: { // int
        const n = 1 << lo;
        if (n === 8) {
          const v = view.getBigInt64(p + 1);
          return Number(v);
        }
        return u(d, p + 1, n);
      }
      case 0x20: // real
        return lo === 2 ? view.getFloat32(p + 1) : view.getFloat64(p + 1);
      case 0x40: { // data
        const [count, q] = readSized(p);
        return d.subarray(q, q + count);
      }
      case 0x50: { // ASCII string
        const [count, q] = readSized(p);
        let s = "";
        for (let i = 0; i < count; i++) s += String.fromCharCode(d[q + i]);
        return s;
      }
      case 0x60: { // UTF-16BE string
        const [count, q] = readSized(p);
        let s = "";
        for (let i = 0; i < count; i++) s += String.fromCharCode(u(d, q + i * 2, 2));
        return s;
      }
      case 0xa0: { // array
        const [count, q] = readSized(p);
        const out = [];
        for (let i = 0; i < count; i++) out.push(readObject(u(d, q + i * refSize, refSize)));
        return out;
      }
      case 0xd0: { // dict
        const [count, q] = readSized(p);
        const out = new Map();
        for (let i = 0; i < count; i++) {
          const k = readObject(u(d, q + i * refSize, refSize));
          const v = readObject(u(d, q + count * refSize + i * refSize, refSize));
          out.set(k, v);
        }
        return out;
      }
      default:
        throw new Error(`Unsupported bplist marker 0x${marker.toString(16)}`);
    }
  }
  return readObject(topObject);
}

/** Marker byte plus extended length, for the 0xF form. */
function sizedHeader(base, count) {
  if (count < 15) return new Uint8Array([base | count]);
  if (count < 0x100) return new Uint8Array([base | 0x0f, 0x10, count]);
  if (count < 0x10000) return concat([new Uint8Array([base | 0x0f, 0x11]), be(count, 2)]);
  return concat([new Uint8Array([base | 0x0f, 0x12]), be(count, 4)]);
}

export class BplistData {
  constructor(bytes) { this.bytes = bytes; }
}

export function buildBplist(root) {
  // Flatten the object graph. Values are not deduplicated except for the small
  // primitives where identity is unambiguous; Photos does not care either way.
  const objects = [];
  const stringIndex = new Map();

  function add(obj) {
    if (typeof obj === "string") {
      if (stringIndex.has(obj)) return stringIndex.get(obj);
      const i = objects.push({ kind: "string", value: obj }) - 1;
      stringIndex.set(obj, i);
      return i;
    }
    if (obj instanceof Uint8Array) return objects.push({ kind: "data", value: obj }) - 1;
    if (typeof obj === "boolean") return objects.push({ kind: "bool", value: obj }) - 1;
    if (typeof obj === "number") {
      const isInt = Number.isInteger(obj) && Math.abs(obj) < 2 ** 63;
      return objects.push({ kind: isInt ? "int" : "real", value: obj }) - 1;
    }
    if (obj instanceof Map) {
      const self = objects.push({ kind: "dict", keys: [], values: [] }) - 1;
      const keys = [...obj.keys()];
      const entry = objects[self];
      entry.keys = keys.map((k) => add(k));
      entry.values = keys.map((k) => add(obj.get(k)));
      return self;
    }
    if (Array.isArray(obj)) {
      const self = objects.push({ kind: "array", items: [] }) - 1;
      objects[self].items = obj.map((v) => add(v));
      return self;
    }
    if (obj === null) return objects.push({ kind: "null" }) - 1;
    throw new Error(`Cannot encode ${typeof obj} in a binary plist`);
  }

  const rootIndex = add(root);
  const refSize = objects.length < 0x100 ? 1 : objects.length < 0x10000 ? 2 : 4;

  function encode(entry) {
    switch (entry.kind) {
      case "null": return new Uint8Array([0x00]);
      case "bool": return new Uint8Array([entry.value ? 0x09 : 0x08]);
      case "int": {
        const v = entry.value;
        if (v >= 0 && v < 0x100) return new Uint8Array([0x10, v]);
        if (v >= 0 && v < 0x10000) return concat([new Uint8Array([0x11]), be(v, 2)]);
        if (v >= 0 && v < 0x100000000) return concat([new Uint8Array([0x12]), be(v, 4)]);
        const b = new Uint8Array(9); b[0] = 0x13;
        new DataView(b.buffer).setBigInt64(1, BigInt(v));
        return b;
      }
      case "real": {
        const b = new Uint8Array(9); b[0] = 0x23;
        new DataView(b.buffer).setFloat64(1, entry.value);
        return b;
      }
      case "data": return concat([sizedHeader(0x40, entry.value.length), entry.value]);
      case "string": {
        const ascii = /^[\x00-\x7f]*$/.test(entry.value);
        if (ascii) {
          const b = new Uint8Array(entry.value.length);
          for (let i = 0; i < b.length; i++) b[i] = entry.value.charCodeAt(i);
          return concat([sizedHeader(0x50, b.length), b]);
        }
        const b = new Uint8Array(entry.value.length * 2);
        for (let i = 0; i < entry.value.length; i++) b.set(be(entry.value.charCodeAt(i), 2), i * 2);
        return concat([sizedHeader(0x60, entry.value.length), b]);
      }
      case "array":
        return concat([sizedHeader(0xa0, entry.items.length),
          ...entry.items.map((i) => be(i, refSize))]);
      case "dict":
        return concat([sizedHeader(0xd0, entry.keys.length),
          ...entry.keys.map((i) => be(i, refSize)),
          ...entry.values.map((i) => be(i, refSize))]);
      default: throw new Error(`Unknown entry ${entry.kind}`);
    }
  }

  const header = new Uint8Array(8);
  "bplist00".split("").forEach((c, i) => { header[i] = c.charCodeAt(0); });
  const encoded = objects.map(encode);
  const offsets = [];
  let pos = header.length;
  for (const e of encoded) { offsets.push(pos); pos += e.length; }
  const offsetTableStart = pos;
  const offsetSize = offsetTableStart < 0x100 ? 1 : offsetTableStart < 0x10000 ? 2 : 4;
  const table = concat(offsets.map((o) => be(o, offsetSize)));
  const trailer = concat([
    new Uint8Array(6), new Uint8Array([offsetSize, refSize]),
    be(objects.length, 8), be(rootIndex, 8), be(offsetTableStart, 8),
  ]);
  return concat([header, ...encoded, table, trailer]);
}
