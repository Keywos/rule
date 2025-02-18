// 改自 https://raw.githubusercontent.com/xream/scripts/main/surge/modules/kill-active-requests/index.sgmodule
const NoPanel = typeof $input == "undefined";
let result = {},
  urlArray = [],
  ReqLength = 0,
  newUrlArray = "",
  KillNum = "";
!(async () => {
  const { requests = [] } = (await httpAPI("/v1/requests/active", "GET")) || {};
  ReqLength = Math.max(requests.length - 1, 0);
  KillNum = "打断活跃请求数: " + ReqLength;
  //console.log(KillNum);

  if (ReqLength != 0) {
    await httpAPI("/v1/dns/flush", "POST");
    // 原本出站规则
    const beforeMode = (await httpAPI()).mode;
    const newMode = { direct: "proxy", proxy: "direct", rule: "proxy" };
    // 切换出站利用surge杀死所有活跃连接
    await httpAPI(undefined, "POST", { mode: `${newMode[beforeMode]}` });
    await httpAPI(undefined, "POST", {
      mode: `${newMode[newMode[beforeMode]]}`,
    });
    // 切换原本出站规则
    await httpAPI(undefined, "POST", { mode: `${beforeMode}` });
    if ((await httpAPI()).mode != beforeMode) {
      await httpAPI(undefined, "POST", { mode: `${beforeMode}` });
    }
  }

  for await (const { URL } of requests) {
    // 太多请求容易卡住
    //await httpAPI("/v1/requests/kill", "POST", { id });
    if (NoPanel) {
      // 通知
      urlArray.push(URL);
    } else {
      // 面板
      const domain = URL.match(/\.([^:/]+)\./)[1] ?? "";
      urlArray.push(domain.replace(/\.(com|net)$/, ""));
      //console.log(URL);
    }
  }

  if (NoPanel) {
    newUrlArray = urlArray.slice(0, -1).join("\n");
    $notification.post(KillNum, "", newUrlArray);
    ReqLength != 0 && console.log("\n\n" + newUrlArray + "\n");
  } else {
    newUrlArray =
      ReqLength === 0 ? "无活跃请求" : urlArray.slice(0, -1).join(", ");
  }

  $done({
    title: KillNum,
    content: newUrlArray,
    icon: "xmark.circle",
    "icon-color": "#C5424A",
  });
})()
  .catch((e) => {
    console.log(e);
  })
  .finally(() => {
    $done(result);
  });

function httpAPI(path = "/v1/outbound", method = "GET", body = null) {
  return new Promise((resolve) => {
    $httpAPI(method, path, body, (result) => {
      resolve(result);
    });
  });
}
