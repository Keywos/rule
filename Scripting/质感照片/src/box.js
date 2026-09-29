// ISO base media file format box reading and writing.
// Mirrors the box helpers in photographic_style_port.py.

export const u = (d, off, n) => {
  let v = 0;
  for (let i = 0; i < n; i++) v = v * 256 + d[off + i];
  return v;
};

export const be = (value, n) => {
  const out = new Uint8Array(n);
  let v = value;
  for (let i = n - 1; i >= 0; i--) { out[i] = v & 0xff; v = Math.floor(v / 256); }
  return out;
};

export const fourcc = (d, off) =>
  String.fromCharCode(d[off], d[off + 1], d[off + 2], d[off + 3]);

/** Iterate sibling boxes in [start, end) as {off, size, hdr, type}. */
export function* boxes(d, start, end) {
  let p = start;
  while (p + 8 <= end) {
    let size = u(d, p, 4);
    const type = fourcc(d, p + 4);
    let hdr = 8;
    if (size === 1) { size = u(d, p + 8, 8); hdr = 16; }
    else if (size === 0) { size = end - p; }
    if (size < hdr || p + size > end) break;
    yield { off: p, size, hdr, type };
    p += size;
  }
}

export function topBox(d, type) {
  for (const b of boxes(d, 0, d.length)) if (b.type === type) return b;
  throw new Error(`Missing top-level ${type} box`);
}

/** meta is a FullBox, so its children start 4 bytes after the header. */
export function metaChildren(d, metaBox) {
  const m = metaBox || topBox(d, "meta");
  return [...boxes(d, m.off + m.hdr + 4, m.off + m.size)];
}

export function findChild(children, type) {
  const b = children.find((c) => c.type === type);
  if (!b) throw new Error(`Missing child box ${type}`);
  return b;
}

export function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Build a box: size + type + payload. */
export function box(type, payload) {
  const t = new Uint8Array(4);
  for (let i = 0; i < 4; i++) t[i] = type.charCodeAt(i);
  return concat([be(8 + payload.length, 4), t, payload]);
}

export const slice = (d, off, len) => d.subarray(off, off + len);

/** Read a null-terminated string, returning [string, positionAfterNull]. */
export function cstring(d, p, end) {
  let q = p;
  while (q < end && d[q] !== 0) q++;
  let s = "";
  for (let i = p; i < q; i++) s += String.fromCharCode(d[i]);
  return [s, Math.min(q + 1, end)];
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return a === b || (!a && !b);
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
