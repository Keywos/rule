//转自@kokoryh
!(function () {
  let e,
    a = JSON.parse($request.body);
  e =
    "0007" === a.placementNo
      ? '{"materialsList":[{"billMaterialsId":"255","filePath":"h","creativeType":1}],"advertParam":{"skipTime":1}}'
      : "G0054" === a.placementNo
      ? '{"code":"00","materialsList":[{}]}'
      : '{"code":"00","message":"无广告返回"}';
  "undefined" != typeof $task
    ? $done({ body: e })
    : $done({ response: { body: e } });
})();
