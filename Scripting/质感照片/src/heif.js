// HEIF item graph: parsing, property lookup, and the surgery the port performs.
// Direct port of the corresponding functions in photographic_style_port.py.

import {
  boxes, topBox, metaChildren, findChild, u, be, box, concat, cstring, slice, bytesEqual,
} from "./box.js";

export const URI_HDR_GAIN = "urn:com:apple:photo:2020:aux:hdrgainmap";
export const URI_LINEAR_THUMB = "tag:apple.com,2023:photo:aux:linearthumbnail";
export const URI_STYLE_DELTA = "tag:apple.com,2023:photo:aux:styledeltamap";
export const URI_STYLES = "tag:apple.com,2023:photo:metadata:styles";
export const DEPTH_URI = "urn:mpeg:hevc:2015:auxid:2";

export const MATTE_URIS = {
  portraiteffectsmatte: "urn:com:apple:photo:2018:aux:portraiteffectsmatte",
  semanticskinmatte: "urn:com:apple:photo:2019:aux:semanticskinmatte",
  semantichairmatte: "urn:com:apple:photo:2019:aux:semantichairmatte",
  semanticteethmatte: "urn:com:apple:photo:2019:aux:semanticteethmatte",
  semanticglassesmatte: "urn:com:apple:photo:2020:aux:semanticglassesmatte",
  semanticskymatte: "urn:com:apple:photo:2020:aux:semanticskymatte",
};
export const MATTE_URI_SET = new Set(Object.values(MATTE_URIS));

export const IROT_IDENTITY = box("irot", new Uint8Array([0]));

const TIFF_TYPE_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };
export { TIFF_TYPE_SIZES };

export function parsePitm(d, metaBox) {
  const b = findChild(metaChildren(d, metaBox), "pitm");
  const version = d[b.off + b.hdr];
  return u(d, b.off + b.hdr + 4, version === 0 ? 2 : 4);
}

export function parseIloc(d, metaBox) {
  const b = findChild(metaChildren(d, metaBox), "iloc");
  let p = b.off + b.hdr;
  const version = d[p];
  p += 4;
  const a = d[p], bb = d[p + 1];
  p += 2;
  const offsetSize = a >> 4, lengthSize = a & 0x0f;
  const baseOffsetSize = bb >> 4;
  const indexSize = (version === 1 || version === 2) ? (bb & 0x0f) : 0;
  const itemCountSize = version < 2 ? 2 : 4;
  const itemCount = u(d, p, itemCountSize);
  p += itemCountSize;
  const items = new Map();
  for (let i = 0; i < itemCount; i++) {
    const iidSize = version < 2 ? 2 : 4;
    const iid = u(d, p, iidSize);
    p += iidSize;
    let constructionMethod = 0;
    if (version === 1 || version === 2) { constructionMethod = u(d, p, 2) & 0x0f; p += 2; }
    p += 2; // data_reference_index
    const baseOffset = baseOffsetSize ? u(d, p, baseOffsetSize) : 0;
    p += baseOffsetSize;
    const extentCount = u(d, p, 2);
    p += 2;
    const extents = [];
    for (let e = 0; e < extentCount; e++) {
      if ((version === 1 || version === 2) && indexSize) p += indexSize;
      const offsetPos = p;
      const extentOffset = offsetSize ? u(d, p, offsetSize) : 0;
      p += offsetSize;
      const lengthPos = p;
      const extentLength = lengthSize ? u(d, p, lengthSize) : 0;
      p += lengthSize;
      extents.push({ offset: extentOffset, length: extentLength, offsetPos, lengthPos });
    }
    items.set(iid, { constructionMethod, baseOffset, extents });
  }
  return { box: b, version, offsetSize, lengthSize, baseOffsetSize, indexSize, items };
}

export function extractItem(d, iloc, iid) {
  const it = iloc.items.get(iid);
  if (!it) throw new Error(`No iloc entry for item ${iid}`);
  if (it.constructionMethod !== 0)
    throw new Error(`Item ${iid} uses construction_method=${it.constructionMethod}`);
  return concat(it.extents.map((e) => slice(d, it.baseOffset + e.offset, e.length)));
}

export function parseIinf(d, metaBox) {
  const b = findChild(metaChildren(d, metaBox), "iinf");
  const version = d[b.off + b.hdr];
  let p = b.off + b.hdr + 4 + (version === 0 ? 2 : 4);
  const out = new Map();
  for (const e of boxes(d, p, b.off + b.size)) {
    if (e.type !== "infe") continue;
    let q = e.off + e.hdr;
    const iv = d[q];
    q += 4;
    if (iv !== 2 && iv !== 3) continue;
    const iidSize = iv === 2 ? 2 : 4;
    const iid = u(d, q, iidSize);
    q += iidSize + 2;
    const itemType = String.fromCharCode(d[q], d[q + 1], d[q + 2], d[q + 3]);
    q += 4;
    const [name, q2] = cstring(d, q, e.off + e.size);
    const info = { type: itemType, name, uri: null, contentType: null };
    if (itemType === "mime") info.contentType = cstring(d, q2, e.off + e.size)[0];
    else if (itemType === "uri ") info.uri = cstring(d, q2, e.off + e.size)[0];
    out.set(iid, info);
  }
  return out;
}

export function parseIref(d, metaBox) {
  const b = findChild(metaChildren(d, metaBox), "iref");
  const version = d[b.off + b.hdr];
  const iidSize = version === 0 ? 2 : 4;
  const refs = [];
  for (const e of boxes(d, b.off + b.hdr + 4, b.off + b.size)) {
    let q = e.off + e.hdr;
    const from = u(d, q, iidSize);
    q += iidSize;
    const count = u(d, q, 2);
    q += 2;
    const to = [];
    for (let i = 0; i < count; i++) { to.push(u(d, q, iidSize)); q += iidSize; }
    refs.push({ type: e.type, from, to });
  }
  return refs;
}

export function parseIpcoIpma(d, metaBox) {
  const m = metaBox || topBox(d, "meta");
  const iprp = findChild(metaChildren(d, m), "iprp");
  const iprpChildren = [...boxes(d, iprp.off + iprp.hdr, iprp.off + iprp.size)];
  const ipco = findChild(iprpChildren, "ipco");
  const ipma = findChild(iprpChildren, "ipma");
  const properties = [];
  let idx = 0;
  for (const b of boxes(d, ipco.off + ipco.hdr, ipco.off + ipco.size)) {
    idx += 1;
    const prop = { index: idx, type: b.type, box: b, auxUri: null, width: null, height: null };
    if (b.type === "auxC") prop.auxUri = cstring(d, b.off + b.hdr + 4, b.off + b.size)[0];
    else if (b.type === "ispe") {
      prop.width = u(d, b.off + b.hdr + 4, 4);
      prop.height = u(d, b.off + b.hdr + 8, 4);
    }
    properties.push(prop);
  }
  let p = ipma.off + ipma.hdr;
  const version = d[p];
  const flags = u(d, p + 1, 3);
  p += 4;
  const entryCount = u(d, p, 4);
  p += 4;
  const wide = Boolean(flags & 1);
  const associations = new Map();
  for (let i = 0; i < entryCount; i++) {
    const iidSize = version === 0 ? 2 : 4;
    const iid = u(d, p, iidSize);
    p += iidSize;
    const ac = d[p];
    p += 1;
    const arr = [];
    for (let a = 0; a < ac; a++) {
      let essential, propIdx;
      if (wide) { const raw = u(d, p, 2); p += 2; essential = Boolean(raw & 0x8000); propIdx = raw & 0x7fff; }
      else { const raw = d[p]; p += 1; essential = Boolean(raw & 0x80); propIdx = raw & 0x7f; }
      if (propIdx) arr.push({ index: propIdx, essential });
    }
    associations.set(iid, arr);
  }
  return { iprpBox: iprp, ipcoBox: ipco, ipmaBox: ipma, properties, associations, version, flags };
}

export function propertyForItem(propinfo, iid, type) {
  for (const a of propinfo.associations.get(iid) || []) {
    const p = propinfo.properties[a.index - 1];
    if (p && p.type === type) return p;
  }
  return null;
}

export function propertyBoxBytes(d, propinfo, iid, type) {
  const p = propertyForItem(propinfo, iid, type);
  return p ? slice(d, p.box.off, p.box.size) : null;
}

export function dimensionsForItem(propinfo, iid) {
  const p = propertyForItem(propinfo, iid, "ispe");
  return p ? [p.width, p.height] : [null, null];
}

export function auxUriForItem(propinfo, iid) {
  const p = propertyForItem(propinfo, iid, "auxC");
  return p ? p.auxUri : null;
}

export function irotAngleForItem(d, propinfo, iid) {
  const b = propertyBoxBytes(d, propinfo, iid, "irot");
  return b ? (b[8] & 3) * 90 : 0;
}

export function imirAxisForItem(d, propinfo, iid) {
  const b = propertyBoxBytes(d, propinfo, iid, "imir");
  return b ? (b[8] & 1) : null;
}

export function displayDimensions(w, h, angle) {
  return (angle === 90 || angle === 270) ? [h, w] : [w, h];
}

export function findItemsByType(infos, type) {
  return [...infos.entries()].filter(([, v]) => v.type === type).map(([k]) => k).sort((a, b) => a - b);
}

export function discoverHeic(d) {
  const meta = topBox(d, "meta");
  const iloc = parseIloc(d, meta);
  const infos = parseIinf(d, meta);
  const refs = parseIref(d, meta);
  const props = parseIpcoIpma(d, meta);
  const primary = parsePitm(d, meta);
  const dimg = new Map();
  for (const r of refs) if (r.type === "dimg") dimg.set(r.from, r.to);
  const primaryTiles = dimg.get(primary) || [];
  if (!primaryTiles.length) throw new Error("Primary image is not a grid/dimg image");
  let thumbnail = null;
  for (const r of refs) if (r.type === "thmb" && r.to.includes(primary)) { thumbnail = r.from; break; }
  let hdrGrid = null, linearThumb = null, deltaGrid = null;
  for (const iid of infos.keys()) {
    const uri = auxUriForItem(props, iid);
    if (uri === URI_HDR_GAIN) hdrGrid = iid;
    else if (uri === URI_LINEAR_THUMB) linearThumb = iid;
    else if (uri === URI_STYLE_DELTA) deltaGrid = iid;
  }
  let stylesItem = null, exifItem = null;
  for (const [iid, info] of infos) {
    if (info.type === "uri " && info.uri === URI_STYLES) stylesItem = iid;
    if (info.type === "Exif") exifItem = iid;
  }
  return {
    meta, iloc, infos, refs, props, primary, primaryTiles, thumbnail, hdrGrid,
    hdrTiles: hdrGrid !== null ? (dimg.get(hdrGrid) || []) : [],
    linearThumb, deltaGrid,
    deltaTiles: deltaGrid !== null ? (dimg.get(deltaGrid) || []) : [],
    stylesItem, exifItem,
  };
}

// ---------------------------------------------------------------- surgery ---

/** Replace an ipco property by index and repair meta/iprp/ipco sizes. */
export function replaceIpcoProperty(meta, propertyIndex, newBox, expectedType) {
  const m = topBox(meta, "meta");
  const props = parseIpcoIpma(meta, m);
  const ipco = props.ipcoBox;
  const list = [...boxes(meta, ipco.off + ipco.hdr, ipco.off + ipco.size)];
  if (propertyIndex < 1 || propertyIndex > list.length)
    throw new Error(`Property index ${propertyIndex} out of range`);
  const old = list[propertyIndex - 1];
  if (expectedType && old.type !== expectedType)
    throw new Error(`Property ${propertyIndex} is ${old.type}, expected ${expectedType}`);
  const delta = newBox.length - old.size;
  const rebuilt = concat([
    slice(meta, 0, old.off), newBox,
    slice(meta, old.off + old.size, meta.length - (old.off + old.size)),
  ]);
  for (const b of [m, props.iprpBox, ipco]) rebuilt.set(be(b.size + delta, 4), b.off);
  return rebuilt;
}

export function replaceItemPropertyWithSource(meta, iid, type, sourceBox) {
  if (!sourceBox) return meta;
  const props = parseIpcoIpma(meta, topBox(meta, "meta"));
  const p = propertyForItem(props, iid, type);
  if (!p) return meta;
  return replaceIpcoProperty(meta, p.index, sourceBox, type);
}

/** Append a property to ipco; every existing index stays valid. */
export function appendIpcoProperty(meta, newBox) {
  const m = topBox(meta, "meta");
  const props = parseIpcoIpma(meta, m);
  const ipco = props.ipcoBox;
  const newIpco = box("ipco", concat([
    slice(meta, ipco.off + ipco.hdr, ipco.size - ipco.hdr), newBox,
  ]));
  const iprp = props.iprpBox;
  const parts = [];
  for (const b of boxes(meta, iprp.off + iprp.hdr, iprp.off + iprp.size))
    parts.push(b.type === "ipco" ? newIpco : slice(meta, b.off, b.size));
  const newIprp = box("iprp", concat(parts));
  const rebuilt = [slice(meta, m.off + m.hdr, 4)];
  for (const b of boxes(meta, m.off + m.hdr + 4, m.off + m.size))
    rebuilt.push(b.type === "iprp" ? newIprp : slice(meta, b.off, b.size));
  return [box("meta", concat(rebuilt)), props.properties.length + 1];
}

/** Point one item's association from oldIndex to newIndex, in place. */
export function repointItemProperty(meta, iid, oldIndex, newIndex) {
  const props = parseIpcoIpma(meta, topBox(meta, "meta"));
  if (props.flags & 1) throw new Error("Wide ipma editing is not supported");
  const ipma = props.ipmaBox;
  const out = meta.slice();
  let p = ipma.off + ipma.hdr + 8;
  const iidSize = props.version === 0 ? 2 : 4;
  const entryCount = u(meta, ipma.off + ipma.hdr + 4, 4);
  for (let i = 0; i < entryCount; i++) {
    const cur = u(meta, p, iidSize);
    p += iidSize;
    const count = out[p];
    p += 1;
    for (let a = 0; a < count; a++) {
      if (cur === iid && (out[p] & 0x7f) === oldIndex) out[p] = (out[p] & 0x80) | newIndex;
      p += 1;
    }
  }
  return out;
}

// A 'mime' entry carries its content type, and a 'uri ' entry its URI, as a second
// null-terminated string after the item name.
const infeBox = (iid, itemType = "hvc1", contentType = null, name = "") => {
  const t = new Uint8Array(4);
  for (let i = 0; i < 4; i++) t[i] = itemType.charCodeAt(i);
  const n = new Uint8Array(name.length + 1);
  for (let i = 0; i < name.length; i++) n[i] = name.charCodeAt(i);
  const parts = [new Uint8Array([2, 0, 0, 1]), be(iid, 2), new Uint8Array([0, 0]), t, n];
  if (contentType !== null) {
    const c = new Uint8Array(contentType.length + 1);
    for (let i = 0; i < contentType.length; i++) c[i] = contentType.charCodeAt(i);
    parts.push(c);
  }
  return box("infe", concat(parts));
};

const refBox = (type, from, toIds) =>
  box(type, concat([be(from, 2), be(toIds.length, 2), ...toIds.map((t) => be(t, 2))]));

export const auxcBox = (uri) => {
  const s = new Uint8Array(uri.length + 1);
  for (let i = 0; i < uri.length; i++) s[i] = uri.charCodeAt(i);
  return box("auxC", concat([new Uint8Array(4), s]));
};

const ipmaEntry = (iid, assoc) => concat([
  be(iid, 2), new Uint8Array([assoc.length]),
  new Uint8Array(assoc.map(([idx, ess]) => {
    if (idx > 0x7f) throw new Error(`Property index ${idx} needs a wide ipma`);
    return (ess ? 0x80 : 0) | idx;
  })),
]);

const ilocEntryV1 = (iid) => concat([
  be(iid, 2), be(0, 2), be(0, 2), be(1, 2), be(0, 4), be(0, 4),
]);

export function ispeBox(w, h) {
  return box("ispe", concat([new Uint8Array(4), be(w, 4), be(h, 4)]));
}

/** Append new items (auxiliary images or mime sidecars) to the item graph. */
export function addItems(meta, specs) {
  if (!specs.length) return [meta, new Map()];
  const m = topBox(meta, "meta");
  const mch = metaChildren(meta, m);
  const props = parseIpcoIpma(meta, m);
  const infos = parseIinf(meta, m);
  const iloc = parseIloc(meta, m);

  let nextIid = Math.max(...infos.keys()) + 1;
  const nextProp = props.properties.length + 1;
  const infes = [], refs = [], ipmas = [], ilocs = [], newProps = [];
  const assigned = new Map();
  specs.forEach((spec, n) => {
    const iid = nextIid + n;
    assigned.set(spec.key ?? spec.uri, iid);
    infes.push(infeBox(iid, spec.itemType || "hvc1", spec.contentType ?? null, spec.itemName || ""));
    if (spec.refTo && spec.refTo.length) refs.push(refBox(spec.refType || "auxl", iid, spec.refTo));
    ilocs.push(ilocEntryV1(iid));
    const assoc = [...(spec.reuse || [])];
    const specBoxes = [...(spec.boxes || [])];
    if (spec.uri || spec.auxc) specBoxes.push(spec.auxc || auxcBox(spec.uri));
    for (const b of specBoxes) {
      newProps.push(b);
      assoc.push([nextProp + newProps.length - 1, String.fromCharCode(b[4], b[5], b[6], b[7]) !== "ispe"]);
    }
    if (assoc.length) ipmas.push(ipmaEntry(iid, assoc));
  });

  // iinf
  const iinf = findChild(mch, "iinf");
  const iinfBody = meta.slice(iinf.off + iinf.hdr, iinf.off + iinf.size);
  const csize = iinfBody[0] === 0 ? 2 : 4;
  iinfBody.set(be(u(iinfBody, 4, csize) + specs.length, csize), 4);
  const newIinf = box("iinf", concat([iinfBody, ...infes]));

  // iref
  const iref = findChild(mch, "iref");
  const newIref = box("iref", concat([slice(meta, iref.off + iref.hdr, iref.size - iref.hdr), ...refs]));

  // iloc
  const ilocBox = findChild(mch, "iloc");
  const ilocBody = meta.slice(ilocBox.off + ilocBox.hdr, ilocBox.off + ilocBox.size);
  const lcsize = iloc.version < 2 ? 2 : 4;
  ilocBody.set(be(u(ilocBody, 6, lcsize) + specs.length, lcsize), 6);
  const newIloc = box("iloc", concat([ilocBody, ...ilocs]));

  // ipco / ipma inside iprp
  const ipco = props.ipcoBox;
  const newIpco = box("ipco", concat([slice(meta, ipco.off + ipco.hdr, ipco.size - ipco.hdr), ...newProps]));
  const ipma = props.ipmaBox;
  const ipmaBody = meta.slice(ipma.off + ipma.hdr, ipma.off + ipma.size);
  ipmaBody.set(be(u(ipmaBody, 4, 4) + ipmas.length, 4), 4);
  const newIpma = box("ipma", concat([ipmaBody, ...ipmas]));
  const iprp = props.iprpBox;
  const iprpParts = [];
  for (const b of boxes(meta, iprp.off + iprp.hdr, iprp.off + iprp.size))
    iprpParts.push(b.type === "ipco" ? newIpco : b.type === "ipma" ? newIpma : slice(meta, b.off, b.size));
  const newIprp = box("iprp", concat(iprpParts));

  const swap = { iinf: newIinf, iref: newIref, iloc: newIloc, iprp: newIprp };
  const rebuilt = [slice(meta, m.off + m.hdr, 4)];
  for (const b of boxes(meta, m.off + m.hdr + 4, m.off + m.size))
    rebuilt.push(swap[b.type] || slice(meta, b.off, b.size));
  return [box("meta", concat(rebuilt)), assigned];
}
