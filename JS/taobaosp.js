let url = $request.url,
  i = JSON.parse($response.body);
if (url.includes("poplayer.template.alibaba.com")) {
  i.res.images = [];
  i.res.videos = [];
  i.enable = false;
  i.props = [];
  i.mainRes = { images: [] };
  
  i.configData.pages = [];
  i.configData.env.bgAlpha = "0";
  i.configData.env.displayDelayMs = 0;
  i.configData.env.autoCloseDelayMs = 0;
} else if (url.includes("wireless.home.splash.awesome.get")) {
  if (i?.data?.containers?.splash_home_base?.base?.sections) {
    i.data.containers.splash_home_base.base.sections.forEach((section) => {
      if ("taobao-splash" in section.bizData) {
        section.bizData["taobao-splash"].data.forEach((i) => {
          for (var key in i) {
            switch (key) {
              case "times":
              case "waitTime":
              case "removeBGDelayMs":
                i[key] = "0";
                break;
              case "gmtStartMs":
              case "startTime":
              case "gmtEndMs":
              case "endTime":
                i[key] = "234775764000";
                break;
              case "imgUrl":
                i[key] = "";
                break;
              case "gmtStart":
                i[key] = "2040-10-25 00:00:00";
                break;
              default:
                if (i[key] === "true") {
                  i[key] = false;
                }
            }
          }
        });
      }
    });
  }
}
$done({ body: JSON.stringify(i) });
