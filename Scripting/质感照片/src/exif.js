// Apple MakerNote surgery: preserve the target's Exif and inject only tag 0x54.
// Port of the corresponding functions in photographic_style_port.py.

import { concat, be } from "./box.js";
import { TIFF_TYPE_SIZES } from "./heif.js";

const tiffU = (d, off, n, little) => {
  let v = 0;
  if (little) { for (let i = n - 1; i >= 0; i--) v = v * 256 + d[off + i]; }
  else { for (let i = 0; i < n; i++) v = v * 256 + d[off + i]; }
  return v;
};

const tiffBytes = (value, n, little) => {
  const b = be(value, n);
  return little ? b.reverse() : b;
};

function locateExifMakerNoteEntry(exifPayload) {
  // The Exif item payload starts with a 4-byte offset to the TIFF header.
  const tiffStart = tiffU(exifPayload, 0, 4, false) + 4;
  const tiff = exifPayload.subarray(tiffStart);
  if (tiff.length < 8) throw new Error("Exif TIFF offset is invalid");
  const order = String.fromCharCode(tiff[0], tiff[1]);
  if (order !== "II" && order !== "MM") throw new Error("Unknown TIFF byte order");
  const little = order === "II";
  const ifd0 = tiffU(tiff, 4, 4, little);
  const n0 = tiffU(tiff, ifd0, 2, little);
  let p = ifd0 + 2;
  let exifIfd = null;
  for (let i = 0; i < n0; i++) {
    if (tiffU(tiff, p, 2, little) === 0x8769) { exifIfd = tiffU(tiff, p + 8, 4, little); break; }
    p += 12;
  }
  if (exifIfd === null) throw new Error("ExifIFD pointer 0x8769 not found");
  const ne = tiffU(tiff, exifIfd, 2, little);
  p = exifIfd + 2;
  for (let i = 0; i < ne; i++) {
    if (tiffU(tiff, p, 2, little) === 0x927c) return { tiffStart, tiff, little, entry: p };
    p += 12;
  }
  throw new Error("Apple MakerNote tag 0x927c not found");
}

export function getMakerNoteBlob(exifPayload) {
  const { tiff, little, entry } = locateExifMakerNoteEntry(exifPayload);
  const typ = tiffU(tiff, entry + 2, 2, little);
  const cnt = tiffU(tiff, entry + 4, 4, little);
  const total = (TIFF_TYPE_SIZES[typ] || 1) * cnt;
  if (total <= 4) return tiff.subarray(entry + 8, entry + 8 + total);
  const off = tiffU(tiff, entry + 8, 4, little);
  return tiff.subarray(off, off + total);
}

export function extractAppleMakerNoteTag(exifPayload, wantedTag = 0x54) {
  const mn = getMakerNoteBlob(exifPayload);
  const sig = String.fromCharCode(...mn.subarray(0, 9));
  if (mn.length < 20 || sig !== "Apple iOS") throw new Error("Unsupported Apple MakerNote");
  const little = String.fromCharCode(mn[12], mn[13]) === "II";
  const n = tiffU(mn, 14, 2, little);
  for (let i = 0; i < n; i++) {
    const p = 16 + i * 12;
    if (tiffU(mn, p, 2, little) !== wantedTag) continue;
    const typ = tiffU(mn, p + 2, 2, little);
    const cnt = tiffU(mn, p + 4, 4, little);
    const total = (TIFF_TYPE_SIZES[typ] || 1) * cnt;
    if (total <= 4) return { type: typ, payload: mn.subarray(p + 8, p + 8 + total) };
    const off = tiffU(mn, p + 8, 4, little);
    return { type: typ, payload: mn.subarray(off, off + total) };
  }
  throw new Error(`Apple MakerNote tag 0x${wantedTag.toString(16)} not found`);
}

/**
 * Preserve the target's Exif and inject or replace one MakerNote tag.
 *
 * The existing MakerNote data area is kept byte for byte: inserting a 12-byte IFD
 * entry shifts it by exactly 12, so only out-of-line value offsets are adjusted.
 * The rebuilt MakerNote is appended at the end of the TIFF block and the outer
 * 0x927c entry is repointed at it, which leaves every other target Exif offset
 * valid. This mirrors the Python implementation exactly.
 */
export function injectAppleMakerNoteTag(exifPayload, payload, wantedTag = 0x54, typ = 7) {
  const { tiffStart, tiff, little: outerLittle, entry } = locateExifMakerNoteEntry(exifPayload);
  const oldMn = getMakerNoteBlob(exifPayload);
  const sig = String.fromCharCode(...oldMn.subarray(0, 9));
  if (oldMn.length < 20 || sig !== "Apple iOS") throw new Error("Unsupported Apple MakerNote");
  const little = String.fromCharCode(oldMn[12], oldMn[13]) === "II";
  const n = tiffU(oldMn, 14, 2, little);
  const tableStart = 16;
  const oldDataStart = tableStart + n * 12 + 4;
  if (oldDataStart > oldMn.length) throw new Error("Truncated Apple MakerNote table");

  const entries = [];
  let found = false;
  for (let i = 0; i < n; i++) {
    const p = tableStart + i * 12;
    const raw = oldMn.slice(p, p + 12);
    const tag = tiffU(raw, 0, 2, little);
    const etyp = tiffU(raw, 2, 2, little);
    const cnt = tiffU(raw, 4, 4, little);
    const total = (TIFF_TYPE_SIZES[etyp] ?? 0) * cnt;
    if (tag === wantedTag) { found = true; continue; }
    entries.push({ tag, raw, total });
  }

  const grow = found ? 0 : 12;
  if (grow) {
    for (const e of entries) {
      if (e.total > 4) {
        const off = tiffU(e.raw, 8, 4, little);
        if (off >= oldDataStart) e.raw.set(tiffBytes(off + grow, 4, little), 8);
      }
    }
  }

  const oldNextPos = tableStart + n * 12;
  const oldNext = tiffU(oldMn, oldNextPos, 4, little);
  const newNext = (grow && oldNext >= oldDataStart && oldNext !== 0) ? oldNext + grow : oldNext;
  const oldData = oldMn.subarray(oldDataStart);

  const newCount = found ? n : n + 1;
  const newDataStart = tableStart + newCount * 12 + 4;
  const newPayloadOff = newDataStart + oldData.length;
  const newEntry = new Uint8Array(12);
  newEntry.set(tiffBytes(wantedTag, 2, little), 0);
  newEntry.set(tiffBytes(typ, 2, little), 2);
  newEntry.set(tiffBytes(payload.length, 4, little), 4);
  if (payload.length <= 4) newEntry.set(payload, 8);
  else newEntry.set(tiffBytes(newPayloadOff, 4, little), 8);
  entries.push({ tag: wantedTag, raw: newEntry, total: payload.length });
  entries.sort((a, b) => a.tag - b.tag);

  const rebuilt = concat([
    oldMn.subarray(0, 14), tiffBytes(newCount, 2, little),
    ...entries.map((e) => e.raw), tiffBytes(newNext, 4, little), oldData,
    payload.length > 4 ? payload : new Uint8Array(0),
  ]);

  const newMnOff = tiff.length;
  const newTiff = concat([tiff, rebuilt]);
  newTiff.set(tiffBytes(7, 2, outerLittle), entry + 2); // UNDEFINED
  newTiff.set(tiffBytes(rebuilt.length, 4, outerLittle), entry + 4);
  newTiff.set(tiffBytes(newMnOff, 4, outerLittle), entry + 8);
  return concat([exifPayload.subarray(0, tiffStart), newTiff]);
}
