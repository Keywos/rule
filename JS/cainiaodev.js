// @Key @RuCu6 2023-06-03 14:45:30
const u = $request.url;
let k = JSON.parse($response.body);
switch (true) {
  case /cainiao\.nbpresentation\.protocol\.homepage\.get\.cn/.test(u):
    if (k.data.result) {
      let res = k.data.result;
      if (res.dataList) {
        res.dataList = res.dataList.filter((i) => {
          if (i.type.includes("kingkong")) { 
            if (i.bizData.items) {
              for (let ii of i.bizData.items) { 
                ii.rightIcon = null;
                ii.bubbleText = null;
              }
              return true;
            }
          } else if (i.type.includes("icons_scroll")) {
            // 顶部图标
            if (i.bizData.items) {
              const item = [
                "bgxq", // 包裹星球
                "cncy", // 填字赚现金
                "cngy", // 免费领水果
                "cngreen", // 绿色家园
                "gjjf", // 裹酱积分
                "jkymd", // 集卡赢免单
                "ljjq", // 领寄件券
                "ttlhb", // 天天领红包
              ];
              i.bizData.items = i.bizData.items.filter(
                (ii) => !item.includes(ii.key)
              );
              for (let ii of i.bizData.items) {
                ii.rightIcon = null;
                ii.bubbleText = null;
              }
              return true;
            }
          } else if (i.type.includes("big_banner_area")) {
            // 新人福利
            return false;
          } else if (i.type.includes("promotion")) {
            // 促销活动
            return false;
          } else {
            return true;
          }
        });
      }
    }
    break;
  case /cainiao\.guoguo\.nbnetflow\.ads\.mshow/.test(u):
    const item = [
      "10", // 物流详情页 底部横图
      "498", // 物流详情页 左上角
      "328", // 3位数为家乡版本
      "366",
      "369",
      "615",
      "616",
      "727",
      "1275", // 支付宝 小程序
      "1308", // 支付宝 小程序
      "1316", // 头部 banner
      "1332", // 我的页面 横图
      "1340", // 查快递 小妙招
    ];
    for (let i of item) {
      if (k.data?.[i]) {
        delete k.data[i];
      }
    }
    break;
  case /nbpresentation\.homepage\.merge\.get\.cn/.test(u):
    if (k.data) {
      // 移除 反馈组件
      const item = [
        "mtop.cainiao.nbmensa.research.researchservice.acquire.cn@0",
        "mtop.cainiao.nbmensa.research.researchservice.acquire.cn@1",
        "mtop.cainiao.nbmensa.research.researchservice.acquire.cn@2",
        "mtop.cainiao.nbmensa.research.researchservice.acquire.cn@3",
      ];
      for (let i of item) {
        if (k.data?.[i]) {
          delete k.data[i];
        }
      }
    }
    break;
  case /nbpresentation\.pickup\.empty\.page\.get\.cn/.test(u):
    if (k.data.result) {
      let ggContent = k.data.result.content;
      if (ggContent.middle) {
        ggContent.middle = ggContent.middle.filter(
          (i) =>
            ![
              "guoguo_pickup_empty_page_relation_add", // 添加亲友
              "guoguo_pickup_helper_feedback", // 反馈组件
              "guoguo_pickup_helper_tip_view", // 取件小助手
            ].includes(i.template.name)
        );
      }
    }
    break;
  case /guoguo\.nbnetflow\.ads\.show\.cn/.test(u):
    if (k.data.result) {
      k.data.result = k.data.result.filter((i) => {
        const group_id = i?.materialContentMapper?.group_id;
        const bgImg = i?.materialContentMapper?.bgImg;
        const adTime = i?.materialContentMapper?.advRecGmtModifiedTime;

        const stakey = i?.materialContentMapper?.adItemDetail; // 开屏
        const hebing = new Set([
          "entertainment",
          "kuaishou_banner",
          "common_header_banner",
          "interests",
        ]); // 底部标签页活动 、快手banner 我的权益
        return !(
          stakey ||
          (group_id && hebing.has(group_id)) ||
          (bgImg && adTime)
        );
      });
    }
    break;
  default:
    break;}
$done({ body: JSON.stringify(k) });

