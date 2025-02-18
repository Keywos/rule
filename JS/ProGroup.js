/* 2023-07-28 13:01:03
作用: 
· 如果策略组 节点变更 会重新缓存结果 重新取值
· 如果有节点偶尔ping不通 那么大概率不会选中他 
· 如果某个节点虽然延迟低 但是速度很差 也不会选他

策略: 
· 根据 api 返回的节点 速度, 延时 (持久化缓存) 对节点进行优选

面板说明:
· 继承: Tokyo: 40C 6.54M 61    [Tokyo]代表优选的节点, [40C]代表次数, [6.54M]代表最高速度, [61]表示综合评分按速度和延时非线性改变
  GroupAuto VPS'4  17:41      [VPS]代表优选的策略组名  ['4]代表策略组中有4个节点

# 必选参数:
# group=          你的策略组名(需要填写手动选择的策略组select)

# 可选参数:
# timeout=6000    单位 ms 最大值9900 Surge Httpapi限制为10s 即 10000ms
# tolerance=10    容差10ms 小于10ms则不切换节点
# timecache=18    缓存到期时间(小时) 或 超过66个数据会清理旧的数据
# avgnumber=30    缓存节点测试次数， 超过会清理
# push            加参数为开启通知, 不加参数则不通知
#!name=GroupAuto
#!desc=根据 api 返回的节点 (速度:持久化缓存非线性权重) 与 (延时:持久化缓存) 对节点进行优选

[Panel]
GroupAuto = script-name=GroupAuto,update-interval=3

[Script]
# 面板 运行 (面板与定时任务可同时存在)
GroupAuto = type=generic,timeout=3,script-path=https://github.com/Keywos/rule/raw/main/JS/ProGroup.js,argument=group=VPS&tolerance=15&timecache=18&color=#6699FF&icon=speedometer
# 定时自动运行(可选需取消#注释) 30分钟一次,每天2到7点不运行
# Cron_GroupAuto = type=cron, cronexp= "0/30 0,1,7-23 * * *", timeout=15,wAllKeye-system=0,script-path=https://raw.githubusercontent.com/Keywos/rule/main/JS/ProGroup.js, argument=tolerance=10&timecache=18&group=Proxy

异常：如遇问题， Surge需要进入[脚本编辑器]→左下角[设置]→[$persistentStore]  [KEY_Group_Auto]删除缓存数据。
*/

let Groupkey = "VPS", tol = "10", th = "18",avgn = "30",isLs=0, fgf = "''", push = false, icons= "",icolor="",debug=1;
if (typeof $argument !== "undefined" && $argument !== "") {
  const ins = getin("$argument");
  Groupkey = ins.group || Groupkey;
  th = ins.timecache || th;
  tol = ins.tolerance || tol;
  push = ins.push || 0;
	debug = ins.debug || 0;
  icons = ins.icon || icons;
  icolor = ins.color || icolor;
  avgn = ins.avgnumber || avgn;
}


function httpAPI(path = "", method = "GET", body = null ) {
  return new Promise((resolve) => {
    $httpAPI(method, path, body, (result) => {
      resolve(result);
    });
  });
}

function getin() {
  return Object.fromEntries(
    $argument.split("&").map((i) => i.split("="))
    .map(([k, v]) => [k, decodeURIComponent(v)])
  );
}

function BtoM(i) {
  var bytes = i / (1024 * 1024);
  if (bytes < 0.01) {return "0.01MB";}
  return bytes.toFixed(2) + "MB";
}
function reSpeed(x, y) {
  if (x > 1e7) {
    return Math.floor(y * 0.6);
  } else{
  const t = x /2e7;
  const ob = 0.99 * Math.exp(-t);
  return Math.floor(y * ob);
  }
}

// 节点数据类
class NodeStats {
  constructor(name) {
    this.name = name;
    this.se = 0;
    this.sum = 0;
	this.sumse = 0;
    this.count = 0;
    this.avg = 0;
    this.sek = 0;
  }
  
  collect(records) {
    for (let record of records) {
      if (record.name === this.name) {
        this.count++;
        const counts = this.count;
        this.sum += record.ms;
        this.se = record.se;
		this.sumse += record.se;
        const tmpAvg = Math.floor(this.sum / counts);
		const seAvg = Math.floor( this.sumse / counts);
        this.avg = tmpAvg;
        this.sek = reSpeed(seAvg, tmpAvg);
      }
    }
  }
}

function getUnia(e){
  e++
  return e
}

function getUni(x) {
  let xhUni;
  let outUni;
  do {
    xhUni = Math.floor(Math.random() * (0x2679 - 0x2673 + 1)) + 0x2673;
    outUni = String.fromCodePoint(xhUni);
  } while (x == outUni);
  return outUni;
}


function NodeData(records) {
  const nodes = {};
  for (let record of Object.values(records)[0]) {
    nodes[record.name] = new NodeStats(record.name);
  }
  for (let record of Object.values(records)) {
    for (let node of Object.values(nodes)) {
      node.collect(record);
    }
  }
  return nodes;
}


(async () => {
  try {
    const proxy = await httpAPI("/v1/policy_groups");
    if (!Object.keys(proxy).includes(Groupkey)) {
      throw new Error("group参数未输入正确的策略组")}
    const Pleng = Object.keys(proxy[Groupkey]).length+" ";// 节点个数
    const NowNodeolicy = await httpAPI(`/v1/policy_groups/select?group_name=${encodeURIComponent(Groupkey)}`);
		// const NowNodeolicy = $surge.selectGroupDetails().decisions[Groupkey];
    let NowNode,resMS,logday=false,logKey="",endDay="",Pushs="",newp="",CC ="",UC="C";
      if (NowNodeolicy) NowNode = NowNodeolicy.policy;
    const Protest = await httpAPI("/v1/policy_groups/test","POST",(body = { group_name: Groupkey }));
      if (Protest){
				fgf = "'";
        if (!NowNodeolicy) NowNode = Protest.available[0];
      }
      if (!NowNode) {throw new Error("无法获取测速结果或策略组信息")}
      // console.log(NowNode)

    const testGroup = await httpAPI("/v1/policies/benchmark_results");
      // /v1/policy_groups  中的 name 和 lineHash 
      resMS = proxy[Groupkey].map((i) => {
        const lineHash = i.lineHash;
        const name = i.name;
        //  /v1/policies/benchmark_results 的 lastTestScoreInMS 为 ms
        let HashValue = testGroup[lineHash];
        if (!HashValue) {
          HashValue = { lastTestScoreInMS: 6996 };
        } else if ( HashValue.lastTestScoreInMS === -1 ) {
          isLs++;
          HashValue.lastTestScoreInMS = 6666;
        }
        const HashMs = HashValue ? HashValue.lastTestScoreInMS : 5678;
        return { name, ms: HashMs, lineHash };
      });
    if ( isLs == Pleng ){
      throw new Error(Groupkey+" 策略组所有节点 Ping 失败, 请检查配置")
    }
    const Sproxy = await httpAPI("/v1/traffic");
      const { connector } = Sproxy;
      const IOM = {}; // inMaxSpeed outMaxSpeed Max
      if (Sproxy.connector) {
        Object.keys(connector).forEach((key) => {
        const { inMaxSpeed, outMaxSpeed, lineHash } = connector[key];
          if (lineHash && inMaxSpeed) {
            IOM[lineHash] = inMaxSpeed + outMaxSpeed;
          }          
        });
      } 
    resMS.forEach((i) => {let lineHash = i.lineHash;
      if (lineHash in IOM) {i.se = IOM[lineHash];} else {i.se = 0;}delete i.lineHash;});
    // console.log(resMS);
    // 读写 清理 超过数量 超过时间戳 缓存
    const nowDay = new Date();
    const tc = nowDay.getTime();
    const readData = $persistentStore.read("KEY_Group_Auto");
      let k = readData ? JSON.parse(readData) : {};
      k[Groupkey] = k[Groupkey] || {};
			const getFunUn = getUni(k['Unicode']) || "♴";
      let ccKey = getUnia(k['ccKey']) || 1, dayKey;
      (ccKey % 10 === 0) && (logday=true)
      if (!k['dayKey']) {
        nowDay.setHours(nowDay.getHours());//+8
        dayKey = String(nowDay.toISOString().slice(0, 10));
        k['dayKey'] = dayKey;logday=true;
      } else {
        dayKey = k['dayKey'];
      }
      
      let timeNms = Object.keys(k[Groupkey]).length;
      for (const t in k[Groupkey]) {
        if (timeNms > (avgn-1)) {
          delete k[Groupkey][t];
          timeNms--;
          UC = " "+getFunUn;
        }
      }
    if (Object.values(k[Groupkey])[0]) {
      const groupValues = Object.values(k[Groupkey])[0];
      if (groupValues.some((i) => !resMS.some((e) => e.name === i.name)) || resMS.some((i) => !groupValues.some((e) => e.name === i.name))) {
          k[Groupkey] = {};logday=true;
          newp="\n数据变更, 清理缓存 !";
        }
    }
    k[Groupkey][tc] = resMS;
    Object.keys(k).forEach((ig) => {const y = k[ig];
      Object.keys(y).forEach((e) => {
        const t = tc - parseInt(e);
        const o = t/(36e5 * th);
        if (o>1) {          
          delete y[e];
        }});
    });
		k['Unicode'] = getFunUn;
    k['ccKey'] = ccKey;
    $persistentStore.write(JSON.stringify(k), "KEY_Group_Auto");
    // console.log(k[Groupkey])
    const AllKey = NodeData(k[Groupkey]);// 函数处理
    const minKey = Object.values(AllKey).map((n) => n.sek);// []
    const minAvg = Math.min(...minKey);// 最优评分
    const minValue = Object.keys(AllKey).find((name) => AllKey[name].sek === minAvg);// 获取对应的节点名称
    const NowNodesek = AllKey[NowNode].sek;// 当前节点评分
    
    if(logday){
      endDay = Math.floor((nowDay - new Date(dayKey)) / (864e5));
      logKey = `自 ${dayKey.slice(2, 10)} 已运行 ${endDay} 天共: ${ccKey} 次`;
    }
    if ( NowNode === minValue ) {
      Pushs ="继承: "+minValue +": "+minAvg;
      CC = BtoM(AllKey[minValue]["se"])+" "+AllKey[minValue]["count"]
    } else if (NowNodesek - minAvg > tol) {
      const selectGroup = $surge.setSelectGroupPolicy(Groupkey,minValue)
      if (!selectGroup) await httpAPI("/v1/policy_groups/select","POST",(body = {group_name: Groupkey, policy: minValue }));
        Pushs ="优选: "+minValue+": "+minAvg;
        CC = BtoM(AllKey[minValue]["se"])+" "+AllKey[minValue]["count"]
    } else {
      Pushs ="容差: "+NowNode+": "+NowNodesek;
      CC = BtoM(AllKey[NowNode]["se"])+" "+AllKey[NowNode]["count"]
    }
    const xt = Groupkey +fgf+Pleng+CC+UC;
    const xc = Pushs+newp;
    // console.log(AllKey)
    console.log("\n"+logKey+"\n"+xt+"\n"+xc);
    push && $notification.post(xt,xc,logKey);
		debug && (console.log(resMS),
		console.log(JSON.stringify(AllKey, null, 2)))

    $done({
      title: xt,
      content: xc,
      icon: icons,
      'icon-color': icolor
    });

  } catch (error) {
    const err = 'Feedback @𝙺𝚎𝚢 !! ';
    console.log(err+error.message)
    push && $notification.post(err,error.message,"");
    $done({title:err, content:error.message})
  }
})();

