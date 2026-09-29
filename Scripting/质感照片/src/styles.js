// Photographic Styles plist edits: scene statistics, c/d light maps, person hint.
// The calibration constants come from eight native files; see the Python source.

import { parseBplist, buildBplist } from "./bplist.js";

export const LIGHTMAP_N = 32;
export const LIGHTMAP_FLOOR = 0.040741;
export const LINEAR_IMAGE_SCALE = 0.166;
export const C_MAP_SLOPE = 0.7774, C_MAP_INTERCEPT = 0.0294;
export const D_MAP_SLOPE = 0.6542, D_MAP_INTERCEPT = -0.0128;

const SCENE_STAT_FIELDS = ["blackPoint", "highKey", "p02", "p10", "p25", "p50", "p75", "p98", "whitePoint"];

export const srgbToLinear = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);

export function percentile(sorted, q) {
  if (!sorted.length) return 0;
  const pos = q * (sorted.length - 1);
  const lo = Math.floor(pos);
  const hi = Math.min(lo + 1, sorted.length - 1);
  const frac = pos - lo;
  return sorted[lo] * (1 - frac) + sorted[hi] * frac;
}

export function statsBlock(sorted, highKey) {
  return new Map([
    ["blackPoint", percentile(sorted, 0.001)],
    ["highKey", highKey],
    ["p02", percentile(sorted, 0.02)],
    ["p10", percentile(sorted, 0.10)],
    ["p25", percentile(sorted, 0.25)],
    ["p50", percentile(sorted, 0.50)],
    ["p75", percentile(sorted, 0.75)],
    ["p98", percentile(sorted, 0.98)],
    ["whitePoint", percentile(sorted, 0.999)],
  ]);
}

/** Rec.709 luma in linear light from packed RGB bytes. */
export function linearLumaFromRgb(rgb) {
  const lut = new Float64Array(256);
  for (let i = 0; i < 256; i++) lut[i] = srgbToLinear(i / 255);
  const out = new Float64Array(rgb.length / 3);
  for (let i = 0, p = 0; p < rgb.length; i++, p += 3)
    out[i] = 0.2126 * lut[rgb[p]] + 0.7152 * lut[rgb[p + 1]] + 0.0722 * lut[rgb[p + 2]];
  return out;
}

const F16 = new DataView(new ArrayBuffer(2));
export function packFloat16LE(values) {
  const out = new Uint8Array(values.length * 2);
  for (let i = 0; i < values.length; i++) {
    F16.setFloat16 ? F16.setFloat16(0, values[i], true) : setHalf(F16, values[i]);
    out[i * 2] = F16.getUint8(0);
    out[i * 2 + 1] = F16.getUint8(1);
  }
  return out;
}

// Manual IEEE-754 half encoding for runtimes without DataView.setFloat16.
function setHalf(view, value) {
  const f = new DataView(new ArrayBuffer(4));
  f.setFloat32(0, value);
  const x = f.getUint32(0);
  const sign = (x >>> 16) & 0x8000;
  let exp = ((x >>> 23) & 0xff) - 127 + 15;
  let mant = x & 0x7fffff;
  let half;
  if (exp <= 0) half = sign;                       // underflow to signed zero
  else if (exp >= 0x1f) half = sign | 0x7c00;      // overflow to infinity
  else half = sign | (exp << 10) | (mant >> 13);
  view.setUint16(0, half, true);
}

/** Build the 32x32 FP16 c/d maps from a linear-luma grid in stored orientation. */
export function buildLightMaps(linearGrid) {
  const grid = Array.from(linearGrid).reverse(); // rot180 == reversing a row-major square
  const make = (slope, intercept) =>
    packFloat16LE(grid.map((v) => Math.max(LIGHTMAP_FLOOR, Math.min(1, slope * v + intercept))));
  return [make(C_MAP_SLOPE, C_MAP_INTERCEPT), make(D_MAP_SLOPE, D_MAP_INTERCEPT)];
}

export function applySceneStatistics(stylesBlob, mode, linearSorted) {
  if (mode === "donor") return [stylesBlob, { sceneStats: "donor", fields: [] }];
  const pl = parseBplist(stylesBlob);
  const six = pl.get("6");
  if (!(six instanceof Map)) return [stylesBlob, { sceneStats: mode, fields: [] }];
  const scaled = linearSorted ? linearSorted.map((v) => v * LINEAR_IMAGE_SCALE) : null;
  const changed = [];
  for (const [name, vals] of [["ToneMappedImage", linearSorted], ["LinearImage", scaled]]) {
    const cur = six.get(name);
    if (!(cur instanceof Map)) continue;
    if (mode === "tone-only" && name === "LinearImage") continue;
    if (mode === "neutral") {
      six.set(name, new Map(SCENE_STAT_FIELDS.map((k) => [k, k === "highKey" ? 1 : 0])));
    } else {
      six.set(name, statsBlock(vals, cur.get("highKey") ?? 1));
    }
    changed.push(name);
  }
  pl.set("6", six);
  return [buildBplist(pl), { sceneStats: mode, fields: changed }];
}

export function applyLightMaps(stylesBlob, cBlob, dBlob) {
  const pl = parseBplist(stylesBlob);
  if (pl.get("e") !== LIGHTMAP_N || pl.get("f") !== LIGHTMAP_N)
    return [stylesBlob, { lightMaps: "flat", note: "styles plist is not 32x32" }];
  const changed = [];
  for (const [key, blob] of [["c", cBlob], ["d", dBlob]]) {
    const cur = pl.get(key);
    if (cur instanceof Uint8Array && cur.length === blob.length) { pl.set(key, blob); changed.push(key); }
  }
  return [buildBplist(pl), { lightMaps: "target", fields: changed }];
}

export function setPersonMasksValid(stylesBlob, valid = 1.0) {
  const pl = parseBplist(stylesBlob);
  const seven = pl.get("7");
  if (!(seven instanceof Map) || !seven.has("PersonMasksValidHint")) return [stylesBlob, null];
  const before = seven.get("PersonMasksValidHint");
  seven.set("PersonMasksValidHint", valid);
  pl.set("7", seven);
  return [buildBplist(pl), before];
}
