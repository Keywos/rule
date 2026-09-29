// iOS 27 Texture/Grain (质感/颗粒). Direct port of add_texture_items / add_texture_bytes in
// photographic_style_port.py (v0.5.0), with the same Apple bytes from iPhone 18 Pro IMG_0309.
//
// Photos offers the controls only when a style photo carries BOTH the texture_styles item
// AND iOS 27's twelve 2026 semantic mattes; the item without the mattes removes the whole
// style palette. For a scene with no people every matte is the same empty 768x576 frame.

import { topBox, metaChildren, findChild, be, concat } from "./box.js";
import {
  discoverHeic, parseIloc, parseIinf, parseIpcoIpma, extractItem, propertyForItem,
  auxUriForItem, findItemsByType, appendIpcoProperty, addItems, auxcBox,
} from "./heif.js";

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (s) => Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
const utf8 = (s) => new TextEncoder().encode(s);

export const URI_TEXTURE_STYLES = "tag:apple.com,2026:photo:metadata:texture_styles";

// Binary plist: Preset Standard, CaptureType LF, CaptureMode Still, PortType PortTypeBack,
// HardwareModel iPhone19,2 (keep it - iPhone16,1 made white areas glow),
// TextureStylePeopleDataVersion 3, FilmGrainSeed 92.
export const TEXTURE_STYLES_BLOB = b64(
  "YnBsaXN0MDDXAQIDBAUGBwgJCgsMDQ5WUHJlc2V0W0NhcHR1cmVUeXBlW0NhcHR1cmVNb2RlWFBv"
  + "cnRUeXBlXUhhcmR3YXJlTW9kZWxfEB1UZXh0dXJlU3R5bGVQZW9wbGVEYXRhVmVyc2lvbl1GaWxt"
  + "R3JhaW5TZWVkWFN0YW5kYXJkUkxGVVN0aWxsXFBvcnRUeXBlQmFja1ppUGhvbmUxOSwyEAMQXAgX"
  + "Hio2P01te4SHjZqlpwAAAAAAAAEBAAAAAAAAAA8AAAAAAAAAAAAAAAAAAACp");

export const MATTE_2026_URIS = [
  "semanticnosematte", "semanticskinmattev2", "semanticnonfaceskinmatte",
  "semanticlipsmatte", "semanticteethmattev2", "semanticpersonmatte",
  "semanticglassesmattev2", "semanticeyebrowsmatte", "semantictattoomatte",
  "semantichandsmatte", "semanticearsmatte", "semanticfaceskinmatte",
].map((n) => `tag:apple.com,2026:photo:aux:${n}`);
const MATTE_ISPE = hex("0000001469737065000000000000030000000240");
const MATTE_PIXI = hex("0000000e70697869000000000108");
const MATTE_HVCC = hex(
  "0000006f68766343010408000000bfc8000000005af000fcfcf8f800000b03a00001001740010c01ffff04"
  + "0800000300bfc800000300005a170240a100010021420101040800000300bfc800000300005ac018080241"
  + "6205e49165537020202008a2000100094401c061d2421014c9");
const MATTE_EMPTY = b64(
  "AAAAmCgBrxJdSi5rFrhWizr/aWc5IydgU/X8AAADAAADAAADAAADARsKDFgAAAMAAAMAAAMAAAMAAAacAAAD"
  + "AAADAAADAAADAAADADygAAADAAADAAADAAADAANSAAADAAADAAADAAADAyoAAAMAAAMAAAMAAHTAAAADAAAD"
  + "AAADAAP8AAADAAADAAADAA6oAAADAAADAAADACgg");
const MATTE_XMP = utf8(
  '<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="XMP Core 6.0.0">\n'
  + '   <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
  + '      <rdf:Description rdf:about=""\n'
  + '            xmlns:fsincMattes="http://ns.apple.com/fsinc/1.0/">\n'
  + "         <fsincMattes:FSINCMatteVersion>0</fsincMattes:FSINCMatteVersion>\n"
  + "      </rdf:Description>\n"
  + "   </rdf:RDF>\n"
  + "</x:xmpmeta>\n");

export function hasTexture(infos) {
  return [...infos.values()].some((i) => i.uri === URI_TEXTURE_STYLES);
}

/**
 * Add every missing 2026 matte (with its XMP sidecar) and the texture_styles item.
 * Returns [meta, Map(itemId -> payload), summary].
 */
export function addTextureItems(meta, primary) {
  const props0 = parseIpcoIpma(meta, topBox(meta, "meta"));
  if (props0.flags & 1) throw new Error("Wide ipma is not supported for adding Texture/Grain items");
  const infos = parseIinf(meta, topBox(meta, "meta"));
  const present = new Set([...infos.keys()].map((i) => auxUriForItem(props0, i)));
  const missing = MATTE_2026_URIS.filter((uri) => !present.has(uri));
  const targets = [primary, ...findItemsByType(infos, "tmap").slice(0, 1)];
  const irot = propertyForItem(props0, primary, "irot");
  const payloads = new Map();

  if (missing.length) {
    // auxC (descriptive) must precede irot (transformative), so associate in native order.
    let ispeI, pixiI, hvccI;
    [meta, ispeI] = appendIpcoProperty(meta, MATTE_ISPE);
    [meta, pixiI] = appendIpcoProperty(meta, MATTE_PIXI);
    [meta, hvccI] = appendIpcoProperty(meta, MATTE_HVCC);
    const specs = [];
    for (const uri of missing) {
      let auxcI;
      [meta, auxcI] = appendIpcoProperty(meta, auxcBox(uri));
      const reuse = [[ispeI, false], [pixiI, false], [auxcI, true], [hvccI, true]];
      if (irot) reuse.push([irot.index, true]);
      specs.push({ key: uri, reuse, refType: "auxl", refTo: targets });
    }
    let mattes, sidecars;
    [meta, mattes] = addItems(meta, specs);
    for (const iid of mattes.values()) payloads.set(iid, MATTE_EMPTY);
    [meta, sidecars] = addItems(meta, missing.map((uri) => ({
      key: `xmp:${uri}`, itemType: "mime", contentType: "application/rdf+xml",
      refType: "cdsc", refTo: [mattes.get(uri)],
    })));
    for (const iid of sidecars.values()) payloads.set(iid, MATTE_XMP);
  }

  let tex;
  [meta, tex] = addItems(meta, [{
    key: "texture", itemType: "uri ", itemName: "metadata",
    contentType: URI_TEXTURE_STYLES, refType: "cdsc", refTo: targets,
  }]);
  payloads.set(tex.get("texture"), TEXTURE_STYLES_BLOB);
  return [meta, payloads, `added #${tex.get("texture")} -> [${targets}], ${missing.length} 2026 mattes`];
}

/**
 * Native iPhone 16/17 style photo -> the same photo plus Texture/Grain. Nothing is ported:
 * existing payloads stay byte-identical, meta grows and every extent offset moves with it,
 * and the new payloads go into one mdat appended at the end.
 */
export function addTexture(data) {
  const d = discoverHeic(data);
  if (d.stylesItem === null) throw new Error("no native Photographic Style");
  if (hasTexture(d.infos)) throw new Error("already has texture_styles");
  const iloc = d.iloc;
  if (iloc.version !== 1 || iloc.offsetSize !== 4 || iloc.lengthSize !== 4
      || iloc.baseOffsetSize !== 0 || iloc.indexSize !== 0)
    throw new Error("unsupported iloc layout");
  const iref = findChild(metaChildren(data, d.meta), "iref");
  if (data[iref.off + iref.hdr] !== 0) throw new Error("unsupported iref version");
  const { off: mo, size: ms } = d.meta;
  const external = new Map([...iloc.items].filter(([, it]) =>
    it.constructionMethod === 0 && it.extents.length));
  for (const it of external.values())
    for (const e of it.extents)
      if (e.offset < mo + ms) throw new Error("payload before end of meta");

  const [newMeta, newPayloads, summary] = addTextureItems(data.slice(mo, mo + ms), d.primary);
  const delta = newMeta.length - ms;
  const metaOut = newMeta.slice();
  const niloc = parseIloc(metaOut, topBox(metaOut, "meta"));
  const tail = data.subarray(mo + ms);
  const cursor = mo + newMeta.length + tail.length + 8;
  const extra = [];
  let extraLen = 0;
  for (const iid of [...newPayloads.keys()].sort((a, b) => a - b)) {
    const e = niloc.items.get(iid).extents[0];
    metaOut.set(be(cursor + extraLen, 4), e.offsetPos);
    metaOut.set(be(newPayloads.get(iid).length, 4), e.lengthPos);
    extra.push(newPayloads.get(iid));
    extraLen += newPayloads.get(iid).length;
  }
  if (cursor + extraLen >= 2 ** 32) throw new Error("file too large for 32-bit offsets");
  for (const [iid, it] of niloc.items)
    if (external.has(iid))
      for (const e of it.extents) metaOut.set(be(e.offset + delta, 4), e.offsetPos);
  const result = concat([
    data.subarray(0, mo), metaOut, tail,
    be(8 + extraLen, 4), new Uint8Array([0x6d, 0x64, 0x61, 0x74]), ...extra,
  ]);

  // Self-check: every original payload byte-identical, every new one readable.
  const check = discoverHeic(result);
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  for (const iid of external.keys())
    if (!same(extractItem(result, check.iloc, iid), extractItem(data, iloc, iid)))
      throw new Error(`self-check failed: item ${iid} changed`);
  for (const [iid, blob] of newPayloads)
    if (!same(extractItem(result, check.iloc, iid), blob))
      throw new Error(`self-check failed: new item ${iid} unreadable`);
  return { data: result, report: { mode: "add-texture", texture: summary, metaGrowth: delta } };
}
