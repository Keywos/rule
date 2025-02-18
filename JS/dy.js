/**
 * 
[Script]
抖音 = type=http-response,pattern=^https:\/\/((tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?|aweme\.snssdk\.com\/aweme\/homepage\/render\/\?),requires-body=1,script-path=https://github.com/Keywos/rule/raw/main/JS/dy.js,max-size=0

[MITM]
hostname = %APPEND% tnc*.zijieapi.com, aweme.snssdk.com

// https://tnc11-aliec2.zijieapi.com/get_domains/v5/?
 */

let url = $request.url;
const TabArr = ["同城", "经验", "热点", "商城"];

if (/(tnc|dm).+\.[^\/]+\.com\/\w+\/v\d\/\?/.test(url)) {
  url = url.replace(/\/\?/g, "");
  const response = {
    status: 302,
    headers: { Location: url },
  };
  $done({ response });
} else if (/aweme\.snssdk\.com\/aweme\/homepage\/render/.test(url)) {
  var i = JSON.parse($response.body);
  if (i?.data?.tab_list) {
    i.data.tab_list.forEach((tab, index) => {
      if (tab.tab_type === "homepage_publish") {
        i.data.tab_list.splice(index, 1);
      } else if (tab.tab_type === "homepage_profile") {
        tab.tab_title = "测试";
      } else if (tab.tab_type === "homepage_home") {
        tab.tab_title = "";
        tab.extra.tab_list = tab.extra.tab_list.filter(
          (tabs) => !TabArr.includes(tabs.tab_title)
        );
      }
    });
  }
  $done({ body: JSON.stringify(i) });
} else {$done()}

