let keyus={日本: "JP", 韩国: "KR", 英国:"UK", 美国:"US", 台湾:"TW", 香港:"HK", 新加坡:"SG", 法国:"FR", 马来西亚:"MY", 菲律宾:"PH", 泰国:"TH", 手动输入:"inkey"},url = $request.url,lk = "",loc = "";
if (typeof $argument !== 'undefined' && $argument !== "") {loc = this.$argument ?? "KR";} else {lk = $persistentStore.read("TikTok解锁地区");loc = keyus[lk] || "KR";if(loc == "inkey"){inkeys = $persistentStore.read("手动输入地区代码[可选]");loc = inkeys;}};
if (/(tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?/.test(url)) {
  url = url.replace(/\/\?/g,'');
  const response = {
    status: 302,
    headers: {Location: url},
  };
  $done({response});
} else if (/_region=CN&|&mcc_mnc=4/.test(url)) {
  url = url.replace(/_region=CN&/g,`_region=${loc}&`).replace(/&mcc_mnc=4/g,"&mcc_mnc=2");
  const response = {
    status: 307,
    headers: {Location: url},
  };
  $done({response});
} else {$done({})};