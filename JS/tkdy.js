/**
 * 
[Script]
抖音 = type=http-response,pattern=^https:\/\/((tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?,requires-body=1,script-path=https://github.com/Keywos/rule/raw/main/JS/tkdy.js,max-size=0

[MITM]
hostname = %APPEND% tnc*.zijieapi.com

// https://tnc11-aliec2.zijieapi.com/get_domains/v5/?
 */

let url = $request.url;
if (/(tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?/.test(url)) {
  $done({ response: { status: 302, headers: { Location: url.replace(/\/\?/g, "") } } });
} else { $done() }