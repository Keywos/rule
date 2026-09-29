// The patch pipeline, ported from cmd_patch in photographic_style_port.py.
//
// The browser build always uses the reuse-thumbnail linearthumbnail, which is the
// on-device-validated path that needs no HEVC encoder. Decoding is only needed for
// the optional target scene statistics and c/d light maps, and is supplied by the
// caller as a `decode` callback so this module stays dependency free.

import { topBox, boxes, be, concat, slice, u } from "./box.js";
import {
  discoverHeic, parseIloc, parseIinf, parseIref, parseIpcoIpma, extractItem,
  propertyForItem, propertyBoxBytes, dimensionsForItem, auxUriForItem,
  irotAngleForItem, imirAxisForItem, displayDimensions, findItemsByType,
  replaceIpcoProperty, replaceItemPropertyWithSource, appendIpcoProperty,
  repointItemProperty, addItems, ispeBox, IROT_IDENTITY,
  MATTE_URIS, MATTE_URI_SET, DEPTH_URI,
} from "./heif.js";
import { injectAppleMakerNoteTag } from "./exif.js";
import { addTextureItems, hasTexture } from "./texture.js";
import {
  applySceneStatistics, applyLightMaps, setPersonMasksValid, buildLightMaps,
  linearLumaFromRgb, LIGHTMAP_N,
} from "./styles.js";

export const VERSION = "0.5.0-web";

// Every rejection a visitor can hit reduces to one of two things: the file is not a
// HEIC at all, or it is a HEIC this build cannot handle. Nothing else is actionable.
export const UNSUPPORTED = "This HEIC isn't supported yet.";

export function selectProfile(index, primaryTiles, hdrTiles) {
  const match = Object.entries(index).filter(
    ([, v]) => v.primary_tiles === primaryTiles && v.hdr_tiles === hdrTiles);
  if (match.length === 1) return match[0][0];
  throw new Error(UNSUPPORTED);
}

/**
 * @param targetData  Uint8Array of the source HEIC
 * @param profile     from loadProfile()
 * @param opts.decode async (targetData, {width,height,angle,mirror}) -> Uint8Array RGB,
 *                    or null to skip target-derived statistics and light maps
 * @param opts.texture false to leave out the iOS 27 Texture/Grain set (v0.4.4 output)
 */
export async function patch(targetData, profile, opts = {}) {
  const td = discoverHeic(targetData);
  if (td.hdrGrid === null || !td.hdrTiles.length) throw new Error(UNSUPPORTED);
  if (td.thumbnail === null || td.exifItem === null) throw new Error(UNSUPPORTED);

  const { manifest } = profile;
  let meta = profile.meta;
  const report = { version: VERSION, warnings: [] };

  if (td.primaryTiles.length !== manifest.primary_tile_count) throw new Error(UNSUPPORTED);
  if (td.hdrTiles.length !== manifest.hdr_tile_count) throw new Error(UNSUPPORTED);

  const payloads = new Map(profile.retained);
  const targetIloc = td.iloc;

  manifest.donor_primary_tiles.forEach((donorIid, i) => {
    payloads.set(Number(donorIid), extractItem(targetData, targetIloc, td.primaryTiles[i]));
  });
  manifest.donor_hdr_tiles.forEach((donorIid, i) => {
    payloads.set(Number(donorIid), extractItem(targetData, targetIloc, td.hdrTiles[i]));
  });
  payloads.set(Number(manifest.donor_thumbnail_item),
    extractItem(targetData, targetIloc, td.thumbnail));

  const targetExif = extractItem(targetData, targetIloc, td.exifItem);
  payloads.set(Number(manifest.donor_exif_item), injectAppleMakerNoteTag(
    targetExif, profile.mn54, 0x54, Number(manifest.smartstyle_makernote_type ?? 7)));

  // Compressed payloads must travel with their own codec/colour configuration.
  const donorPrimary0 = Number(manifest.donor_primary_tiles[0]);
  const targetPrimary0 = td.primaryTiles[0];
  meta = replaceItemPropertyWithSource(meta, donorPrimary0, "hvcC",
    propertyBoxBytes(targetData, td.props, targetPrimary0, "hvcC"));
  meta = replaceItemPropertyWithSource(meta, donorPrimary0, "colr",
    propertyBoxBytes(targetData, td.props, targetPrimary0, "colr"));
  const donorThumb = Number(manifest.donor_thumbnail_item);
  meta = replaceItemPropertyWithSource(meta, donorThumb, "hvcC",
    propertyBoxBytes(targetData, td.props, td.thumbnail, "hvcC"));
  meta = replaceItemPropertyWithSource(meta, donorThumb, "colr",
    propertyBoxBytes(targetData, td.props, td.thumbnail, "colr"));
  meta = replaceItemPropertyWithSource(meta, Number(manifest.donor_hdr_tiles[0]), "hvcC",
    propertyBoxBytes(targetData, td.props, td.hdrTiles[0], "hvcC"));

  // Orientation: the donor's shared irot drives the whole item graph.
  const donorPrimary = Number(manifest.donor_primary_item);
  const targetAngle = irotAngleForItem(targetData, td.props, td.primary);
  const targetMirror = imirAxisForItem(targetData, td.props, td.primary);
  const donorAngle = irotAngleForItem(meta, parseIpcoIpma(meta, topBox(meta, "meta")), donorPrimary);
  meta = replaceItemPropertyWithSource(meta, donorPrimary, "irot",
    propertyBoxBytes(targetData, td.props, td.primary, "irot") || IROT_IDENTITY);
  if (targetMirror !== null) {
    const now = parseIpcoIpma(meta, topBox(meta, "meta"));
    if (!propertyForItem(now, donorPrimary, "imir"))
      report.warnings.push("target has an imir property but the profile has no slot for it");
    else
      meta = replaceItemPropertyWithSource(meta, donorPrimary, "imir",
        propertyBoxBytes(targetData, td.props, td.primary, "imir"));
  }
  report.orientation = { donor: donorAngle, target: targetAngle, mirror: targetMirror };

  // tmap declares display geometry and carries its own irot, so it must follow the target.
  const donorTmaps = findItemsByType(parseIinf(meta, topBox(meta, "meta")), "tmap");
  const targetTmaps = findItemsByType(td.infos, "tmap");
  if (donorTmaps.length) {
    const donorTmap = donorTmaps[0];
    let srcIspe, srcIrot;
    if (targetTmaps.length) {
      srcIspe = propertyBoxBytes(targetData, td.props, targetTmaps[0], "ispe");
      srcIrot = propertyBoxBytes(targetData, td.props, targetTmaps[0], "irot");
    } else {
      const [pw, ph] = dimensionsForItem(td.props, td.primary);
      const [dw, dh] = displayDimensions(pw, ph, targetAngle);
      srcIspe = ispeBox(dw, dh);
      srcIrot = IROT_IDENTITY;
    }
    meta = replaceItemPropertyWithSource(meta, donorTmap, "ispe", srcIspe);
    meta = replaceItemPropertyWithSource(meta, donorTmap, "irot", srcIrot || IROT_IDENTITY);
    report.tmap = dimensionsForItem(parseIpcoIpma(meta, topBox(meta, "meta")), donorTmap);
  }

  // Semantic mattes and depth.
  const donorProps = parseIpcoIpma(meta, topBox(meta, "meta"));
  const donorInfos = parseIinf(meta, topBox(meta, "meta"));
  const donorSlots = new Map(), targetSlots = new Map();
  for (const iid of donorInfos.keys()) {
    const uri = auxUriForItem(donorProps, iid);
    if (uri && MATTE_URI_SET.has(uri)) donorSlots.set(uri, iid);
  }
  for (const iid of td.infos.keys()) {
    const uri = auxUriForItem(td.props, iid);
    if (uri && MATTE_URI_SET.has(uri)) targetSlots.set(uri, iid);
  }
  report.mattes = { transplanted: [], added: [], neutralized: [] };
  let assigned = new Map();
  if (donorSlots.size) {
    const templateIid = donorSlots.values().next().value;
    const templateRefs = parseIref(meta, topBox(meta, "meta"))
      .filter((r) => r.type === "auxl" && r.from === templateIid).map((r) => r.to);
    const toIds = templateRefs.length ? templateRefs[0] : [td.primary];
    const specs = [];

    if (targetSlots.size) {
      const shared = [...targetSlots.keys()].filter((k) => donorSlots.has(k));
      const extra = [...targetSlots.keys()].filter((k) => !donorSlots.has(k));
      const spare = [...donorSlots.keys()].filter((k) => !targetSlots.has(k));
      const anyTarget = targetSlots.values().next().value;
      const [m2, newHvcc] = appendIpcoProperty(meta,
        propertyBoxBytes(targetData, td.props, anyTarget, "hvcC"));
      meta = m2;
      const oldHvcc = propertyForItem(donorProps, donorSlots.get(shared[0]), "hvcC").index;
      for (const uri of shared) {
        meta = repointItemProperty(meta, donorSlots.get(uri), oldHvcc, newHvcc);
        meta = replaceItemPropertyWithSource(meta, donorSlots.get(uri), "auxC",
          propertyBoxBytes(targetData, td.props, targetSlots.get(uri), "auxC"));
        payloads.set(donorSlots.get(uri),
          extractItem(targetData, targetIloc, targetSlots.get(uri)));
        report.mattes.transplanted.push(uri.split(":").pop());
      }
      const neutralSrc = donorSlots.get(MATTE_URIS.portraiteffectsmatte);
      for (const uri of spare) {
        if (neutralSrc !== undefined && payloads.has(donorSlots.get(uri))) {
          payloads.set(donorSlots.get(uri), profile.retained.get(neutralSrc));
          report.mattes.neutralized.push(uri.split(":").pop());
        }
      }
      const nowProps = parseIpcoIpma(meta, topBox(meta, "meta"));
      const templateAssoc = nowProps.associations.get(templateIid);
      const templateAuxc = propertyForItem(nowProps, templateIid, "auxC");
      const matteReuse = templateAssoc.filter((a) => a.index !== templateAuxc.index)
        .map((a) => [a.index, a.essential]);
      for (const uri of extra)
        specs.push({
          key: uri, uri, reuse: matteReuse, boxes: [],
          auxc: propertyBoxBytes(targetData, td.props, targetSlots.get(uri), "auxC"),
        });
    }

    // Depth is independent of the mattes: a Portrait photo of a non-person subject
    // carries depth with no mattes at all.
    const depthIds = [...td.infos.keys()].filter((i) => auxUriForItem(td.props, i) === DEPTH_URI);
    const donorDepth = [...donorInfos.keys()].filter((i) => auxUriForItem(donorProps, i) === DEPTH_URI);
    if (depthIds.length && !donorDepth.length) {
      const di = depthIds[0];
      const irotProp = propertyForItem(parseIpcoIpma(meta, topBox(meta, "meta")), templateIid, "irot");
      const boxesForDepth = ["ispe", "pixi", "colr", "hvcC"]
        .map((t) => propertyBoxBytes(targetData, td.props, di, t)).filter(Boolean);
      specs.push({
        key: DEPTH_URI, uri: DEPTH_URI,
        reuse: irotProp ? [[irotProp.index, true]] : [],
        boxes: boxesForDepth,
        auxc: propertyBoxBytes(targetData, td.props, di, "auxC"),
      });
      targetSlots.set(DEPTH_URI, di);
    }

    for (const s of specs) { s.refType = "auxl"; s.refTo = toIds; }
    if (specs.length) {
      const [m3, a] = addItems(meta, specs);
      meta = m3; assigned = a;
      for (const [uri, newIid] of assigned) {
        payloads.set(newIid, extractItem(targetData, targetIloc, targetSlots.get(uri)));
        report.mattes.added.push(`${uri === DEPTH_URI ? "depth" : uri.split(":").pop()}#${newIid}`);
      }
    }

    // XMP sidecars: every auxiliary is interpreted through a mime item pointed at it
    // by cdsc. The depth sidecar carries the Portrait blur parameters.
    const portInfos = parseIinf(meta, topBox(meta, "meta"));
    const portRefs = parseIref(meta, topBox(meta, "meta"));
    const idMap = new Map([[td.primary, Number(manifest.donor_primary_item)]]);
    if (td.hdrGrid !== null) idMap.set(td.hdrGrid, Number(manifest.donor_hdr_grid_item));
    const portTmaps = findItemsByType(portInfos, "tmap");
    targetTmaps.forEach((t, i) => { if (portTmaps[i] !== undefined) idMap.set(t, portTmaps[i]); });
    for (const [uri, tiid] of targetSlots) {
      if (donorSlots.has(uri)) idMap.set(tiid, donorSlots.get(uri));
      else if (assigned.has(uri)) idMap.set(tiid, assigned.get(uri));
    }
    const portCdsc = new Map(portRefs.filter((r) => r.type === "cdsc").map((r) => [r.from, r.to]));
    const described = new Map();
    for (const [iid, info] of portInfos)
      if (info.type === "mime" && portCdsc.has(iid))
        described.set(portCdsc.get(iid).join(","), iid);
    const targetCdsc = new Map(td.refs.filter((r) => r.type === "cdsc").map((r) => [r.from, r.to]));
    const sidecarSpecs = [];
    for (const [tiid, info] of [...td.infos.entries()].sort((a, b) => a[0] - b[0])) {
      if (info.type !== "mime" || !targetCdsc.has(tiid)) continue;
      const tgts = targetCdsc.get(tiid);
      if (!tgts.every((t) => idMap.has(t))) continue;
      const mapped = tgts.map((t) => idMap.get(t));
      const payload = extractItem(targetData, targetIloc, tiid);
      const key = mapped.join(",");
      if (described.has(key)) payloads.set(described.get(key), payload);
      else sidecarSpecs.push({
        key: `mime${tiid}`, itemType: "mime",
        contentType: info.contentType || "application/rdf+xml",
        refType: "cdsc", refTo: mapped, _payload: payload,
      });
    }
    if (sidecarSpecs.length) {
      const [m4, sc] = addItems(meta, sidecarSpecs);
      meta = m4;
      for (const s of sidecarSpecs) payloads.set(sc.get(s.key), s._payload);
      report.sidecarsAdded = sidecarSpecs.length;
    }
  }

  // iOS 27 Texture/Grain set (2026 mattes + texture_styles). Appending keeps every existing
  // property index, so the manifest's linearthumbnail hvcC index below still holds.
  report.texture = "off";
  if (opts.texture !== false) {
    const portInfos = parseIinf(meta, topBox(meta, "meta"));
    if (hasTexture(portInfos)) report.texture = "from profile";
    else {
      const [m6, texPayloads, summary] = addTextureItems(meta, Number(manifest.donor_primary_item));
      meta = m6;
      for (const [iid, blob] of texPayloads) payloads.set(iid, blob);
      report.texture = summary;
    }
  }

  // Linearthumbnail: reuse the target's own thumbnail, no encoder needed.
  const donorLt = Number(manifest.donor_linear_thumb_item);
  const thumbHvcc = propertyBoxBytes(targetData, td.props, td.thumbnail, "hvcC");
  payloads.set(donorLt, extractItem(targetData, targetIloc, td.thumbnail));
  meta = replaceIpcoProperty(meta, Number(manifest.linear_thumb_hvcc_property_index),
    thumbHvcc, "hvcC");
  meta = replaceItemPropertyWithSource(meta, donorLt, "ispe",
    propertyBoxBytes(targetData, td.props, td.thumbnail, "ispe"));
  const srcPixi = propertyBoxBytes(targetData, td.props, td.thumbnail, "pixi");
  const curPixi = propertyForItem(parseIpcoIpma(meta, topBox(meta, "meta")), donorLt, "pixi");
  if (srcPixi && curPixi) {
    const oldPixi = propertyBoxBytes(meta, parseIpcoIpma(meta, topBox(meta, "meta")), donorLt, "pixi");
    if (!oldPixi || oldPixi.length !== srcPixi.length
        || oldPixi.some((v, i) => v !== srcPixi[i])) {
      // pixi is shared with the delta grid and tmap, so append rather than overwrite.
      const [m5, idx] = appendIpcoProperty(meta, srcPixi);
      meta = repointItemProperty(m5, donorLt, curPixi.index, idx);
    }
  }
  report.linearThumb = dimensionsForItem(parseIpcoIpma(meta, topBox(meta, "meta")), donorLt);

  // Styles plist edits.
  const donorStyles = Number(manifest.donor_styles_item);
  if (payloads.has(donorStyles)) {
    let blob = payloads.get(donorStyles);
    // Measuring the photo is an enhancement, never a requirement. A decoder that is
    // missing, blocked or simply broken must cost quality, not the whole port - so
    // failures here fall back to the donor values rather than propagating.
    // A decoder that returns the wrong number of samples is worse than one that
    // throws: the statistics would come out silently wrong. Check the size.
    const measure = async (req) => {
      const rgb = await opts.decode(targetData, req);
      const need = req.width * req.height * 3;
      if (!rgb || rgb.length !== need)
        throw new Error(`decoder returned ${rgb ? rgb.length : 0} bytes, expected ${need}`);
      return rgb;
    };

    let sorted = null;
    report.decoded = false;
    if (opts.decode && opts.sceneStats !== "donor") {
      try {
        const rgb = await measure({ width: 256, height: 192 });
        sorted = Array.from(linearLumaFromRgb(rgb)).sort((a, b) => a - b);
        report.decoded = true;
      } catch (e) {
        sorted = null;
        report.decodeError = (e && e.message) || String(e);
      }
    }
    const [b1, sr] = applySceneStatistics(blob, sorted ? (opts.sceneStats || "target") : "donor", sorted);
    blob = b1;
    report.sceneStats = sr;
    if (opts.decode && opts.lightMaps === "target" && report.decoded) {
      try {
        const grid = await measure({
          width: LIGHTMAP_N, height: LIGHTMAP_N, angle: targetAngle, mirror: targetMirror,
        });
        const [c, dmap] = buildLightMaps(linearLumaFromRgb(grid));
        const [b2, mr] = applyLightMaps(blob, c, dmap);
        blob = b2;
        report.lightMaps = mr;
      } catch (e) {
        report.decodeError = (e && e.message) || String(e);
      }
    }
    if (report.mattes.transplanted.length) {
      const [b3, before] = setPersonMasksValid(blob);
      blob = b3;
      report.personMasksValidHint = `${before} -> 1.0`;
    }
    payloads.set(donorStyles, blob);
  }

  // Rebuild one clean mdat and rewrite every external extent.
  const profileIloc = parseIloc(meta, topBox(meta, "meta"));
  const externalIds = [...profileIloc.items.entries()]
    .filter(([, it]) => it.constructionMethod === 0 && it.extents.length)
    .map(([iid]) => iid).sort((a, b) => a - b);
  const missing = externalIds.filter((i) => !payloads.has(i));
  if (missing.length) throw new Error(`Profile is missing payload(s): ${missing}`);

  const mdatStart = profile.ftyp.length + meta.length;
  let cursor = mdatStart + 8;
  const chunks = [];
  const layout = new Map();
  for (const iid of externalIds) {
    const blob = payloads.get(iid);
    layout.set(iid, [cursor, blob.length]);
    chunks.push(blob);
    cursor += blob.length;
  }
  const metaOut = meta.slice();
  const iloc2 = parseIloc(metaOut, topBox(metaOut, "meta"));
  for (const [iid, [off, len]] of layout) {
    const e = iloc2.items.get(iid).extents[0];
    metaOut.set(be(off, iloc2.offsetSize), e.offsetPos);
    metaOut.set(be(len, iloc2.lengthSize), e.lengthPos);
  }
  const mdatPayload = concat(chunks);
  const result = concat([
    profile.ftyp, metaOut, be(8 + mdatPayload.length, 4),
    new Uint8Array([0x6d, 0x64, 0x61, 0x74]), mdatPayload,
  ]);
  return { data: result, report };
}
