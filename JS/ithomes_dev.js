const isLoon = typeof $loon !== "undefined";
let lbt = true,
  zd = true,
  lbtAd = true;
if (isLoon) {
  lbtAd = $persistentStore.read("去除轮播图广告") === "开启";
  lbt = $persistentStore.read("去除整个轮播图") === "开启";
  zd = $persistentStore.read("去除置顶") === "开启";
}
let FeedTypes = [];

let i = JSON.parse($response.body);
if (i?.data?.list) {
  if (lbtAd && !lbt) {
    for (const Type of i.data.list) {
      if (Type.feedType === 10002) {
        Type.feedContent.focusNewsData = Type.feedContent.focusNewsData.filter(
          (i) => {
            return i.isAd === false; // 轮播图广告
          }
        );
        break;
      }
    }
  }
  lbt && FeedTypes.push(10002); //轮播
  zd && FeedTypes.push(10003); //置顶
  i.data.list = i.data.list.filter((item) => {
    return (
      !FeedTypes.includes(item.feedType) &&
      !item.feedContent.smallTags?.[0].text.includes("广告")
    );
  });
}
$done({ body: JSON.stringify(i) });
