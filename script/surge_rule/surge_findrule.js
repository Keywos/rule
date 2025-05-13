// 2025-05-13 14:05:26
(async () => {
  // prettier-ignore
  let body = { d: "", p: "" }, response = { body: JSON.stringify(body) }, ARGV, reqbody, notif = "空数据"
  try {
    const CACHE_KEY = "Rule-Cidr-Cache"; // whois cidr 缓存
    const CACHE_TTL = 90 * 24 * 60 * 60 * 1000; // cidr 结果 缓存过期时间 90天 毫秒
    try {
      reqbody = JSON.parse($request?.body);
    } catch (error) {
      throw new Error("$request.body 解析错误" + error.message);
    }
    try {
      ARGV = JSON.parse($argument);
    } catch (error) {
      throw new Error("$argument 解析错误" + error.message);
    }
    // prettier-ignore
    const { CN = "CNN", FINAL = "FINAL", COUNT = 5, CNIP = 1, CNHOST = 1, FINALIP = 1,  FINALHOST = 1,} = ARGV;
    var checkCacheCidrs = [];
    if (FINALIP && CNIP) checkCacheCidrs = ReadValidCache();
    var _cidr_cache = 0;
    var _cidr_get = 0;
    var _cidr_size = 0;
    var rules_re_other_set = new Set(); // 去重
    var rules_re_domain_set = new Set(); // 去重
    var rules_re_keyword_set = new Set(); // 去除 KEYWORD 命中的
    // - "it"
    // prettier-ignore
    const countryTLDList = [ "cn", "us", "uk", "jp", "de", "fr", "au", "ca", "ru", "kr", "sg", "in", "tw", "hk", "mo", "nl", "es", "ch", "se","no", "fi", "dk", "be", "br", "mx", "ar", "za", "nz", "il"];
    const lines = reqbody.input_csv
      ? reqbody.input_csv.trim()?.split("\n")
      : [];

    const {
      excludeRules: file_directs_o,
      otherRules: file_directs,
      fileLength: file_directs_l,
    } = parseRulesAll(reqbody.file_direcr);

    const {
      excludeRules: file_proxys_o,
      otherRules: file_proxys,
      fileLength: file_proxys_l,
    } = parseRulesAll(reqbody.file_proxy);

    console.log("INCSV: \t" + lines?.length);
    console.log("PROXY: \t" + file_proxys_l);
    console.log("DIRECT: \t" + file_directs_l);

    const today = new Date().toLocaleString("zh-CN", { hour12: false });
    const proxyList = [];
    const directList = [];
    const proxyRegex = new RegExp(FINAL);
    const directRegex = new RegExp(CN);

    const RULEOBJ = {
      DIRECT: { hosts: [], ips: [] },
      PROXY: { hosts: [], ips: [] },
    };

    for (let i = 0; i < lines?.length; i++) {
      const line = lines[i];
      const c1 = line.indexOf(",");
      const c2 = line.indexOf(",", c1 + 1);
      const c3 = line.indexOf(",", c2 + 1);
      const c4 = line.indexOf(",", c3 + 1);
      const H = line.slice(0, c1);
      const P = line.slice(c1 + 1, c2);
      const C = Number(line.slice(c3 + 1, c4));
      if (C < COUNT) continue;
      if (proxyRegex.test(P)) {
        proxyList.push(H);
      } else if (directRegex.test(P)) {
        directList.push(H);
      }
    }
    const isIPv4 = (str) => /^\d+\.\d+\.\d+\.\d+$/.test(str);
    const isIPv6 = (str) => /^([0-9a-fA-F]{1,4}:){2,7}/.test(str);

    for (let i = 0; i < directList.length; i++) {
      const H = directList[i];
      if (isIPv4(H)) {
        if (CNIP) RULEOBJ.DIRECT.ips.push(H);
      } else if (CNHOST && !isIPv6(H)) {
        RULEOBJ.DIRECT.hosts.push(`DOMAIN-SUFFIX,${H}`);
      }
    }

    for (let i = 0; i < proxyList.length; i++) {
      const H = proxyList[i];
      if (isIPv4(H)) {
        if (FINALIP) RULEOBJ.PROXY.ips.push(H);
      } else if (FINALHOST && !isIPv6(H)) {
        RULEOBJ.PROXY.hosts.push(`DOMAIN-SUFFIX,${H}`);
      }
    }

    const rule_direct_cidr = await CidrRules(RULEOBJ.DIRECT.ips);

    var notif_text_a = [];
    var notif_text_b = [];
    var notif_text_c = [];
    var notif_text_d = [];
    let dset;

    try {
      dset = new Set([
        ...file_directs, // file_direcr
        ...rule_direct_cidr,
        ...RULEOBJ.DIRECT.hosts,
      ]);
    } catch (error) {
      throw new Error("未传入数据." + error.message);
    }
    let { rules: rules_direct, count: count_direct } = processRules(
      dset,
      (is_direct = true)
    );
    const rule_proxy_cidr = await CidrRules(RULEOBJ.PROXY.ips);
    let rset;

    try {
      rset = new Set([
        ...file_proxys, //file_proxy
        ...rule_proxy_cidr,
        ...RULEOBJ.PROXY.hosts,
      ]);
    } catch (error) {
      throw new Error("未传入数据.." + error.message);
    }
    let { rules: rules_proxy, count: count_proxy } = processRules(rset);

    rules_direct =
      `# 手动规则: 以下规则优先级最高 不参与规则数量统计\n${file_directs_o.join(
        "\n"
      )}\n\n# 更新时间: ${today}\n# 规则数量：当前共 ${
        count_direct || 0
      } 条规则\n\n` + rules_direct;

    rules_proxy =
      `# 手动规则: 以下规则优先级最高 不参与规则数量统计\n${file_proxys_o.join(
        "\n"
      )}\n\n# 更新时间: ${today}\n# 规则数量：当前共 ${
        count_proxy || 0
      } 条规则\n\n` + rules_proxy;

    // console.log("\nrules_direct\n");
    // console.log(rules_direct);

    // console.log("\nrules_proxy\n");
    // console.log(rules_proxy);

    const notif_text =
      count_direct != file_directs_l
        ? `${file_directs_l} -> ${count_direct}`
        : `${count_direct}`;
    const notif_textp =
      file_proxys_l != count_proxy
        ? `${file_proxys_l} -> ${count_proxy}`
        : `${count_proxy}`;

    if (notif_text != "0") {
      notif += `${CN}: ${notif_text}  `;
    }
    if (notif_textp != "0") {
      notif += `${FINAL}: ${notif_textp}  `;
    }
    if (_cidr_get > 0) {
      notif += `\nIP-CIDR: 请求查询:${_cidr_get}, 缓存${_cidr_cache}, 最终规则:${_cidr_size}`;
    }
    $notification.post("FindRule", "", notif);
    let t =
      notif_text_a.length > 0
        ? `\n\n去掉 [${CN}] 里有的规则:\n${notif_text_a.join("\n")}\n`
        : "";
    t +=
      notif_text_b.length > 0
        ? `\n\n去掉命中 KEYWORD 的规则: \n${notif_text_b.join("\n")}\n`
        : "";
    t +=
      notif_text_c.length > 0
        ? `\n\n去掉命中 国家顶级域名 的规则: \n${notif_text_c.join("\n")}\n`
        : "";
    t +=
      notif_text_d.length > 0
        ? `\n\n去掉命中 手动规则 的规则: \n${notif_text_d.join("\n")}\n`
        : "";
    t += "\n\n" + notif + "\n";

    console.log(t);

    response.body = JSON.stringify({ d: rules_direct, p: rules_proxy });

    function processRules(ruleSet, is_direct = false) {
      let isdp = is_direct ? CN : FINAL;
      const rules_other_set = new Set();
      const rules_direct_set = new Set(); // 最终规则

      let rule_split = [];
      for (const item of ruleSet) {
        const [type, ...domainParts] = item.split(",");
        if (domainParts.length === 0) continue;
        const domain = domainParts.join(",").trim().replace(/\s+/g, "");
        rule_split.push([type, domain]);
        if (type === "DOMAIN-KEYWORD") {
          rules_re_keyword_set.add(domain);
        }
      }
      rule_split.forEach((i) => {
        const type = i[0];
        const domain = i[1];
        if (type === "DOMAIN-SUFFIX") {
          const parts = domain.split(".");
          const parts_length = parts.length;

          if (rules_re_other_set.has(domain)) {
            notif_text_d.push(isdp + ": " + domain);
            return;
          }

          if (is_direct) {
            rules_re_domain_set.add(domain);
          } else {
            if (rules_re_domain_set.has(domain)) {
              notif_text_a.push(isdp + ": " + domain);
              return;
            }
          }

          if (parts_length > 0) {
            const tlddomain = parts[parts_length - 1];
            if (countryTLDList.includes(tlddomain)) {
              if (parts_length > 1) {
                if (!is_direct && rules_re_domain_set.has(tlddomain)) {
                  notif_text_a.push(isdp + ": " + tlddomain);
                  return;
                } else {
                  notif_text_c.push(isdp + ": " + tlddomain + " -> " + domain);
                  rules_direct_set.add("DOMAIN-SUFFIX," + tlddomain);
                }
              }
            } else {
              if (!checkMatch(domain)) {
                if (parts_length > 2) {
                  // 提取主域名
                  const doma = parts.slice(-2).join(".");
                  is_direct && rules_re_domain_set.add(doma);
                  rules_direct_set.add("DOMAIN-SUFFIX," + doma);
                } else {
                  rules_direct_set.add("DOMAIN-SUFFIX," + domain);
                }
              }
            }
          }
        } else {
          let matchkey = false;
          if (type === "IP-CIDR") {
            if (checkMatch(domain)) {
              matchkey = true;
            }
          }
          if (!matchkey) rules_other_set.add(type + "," + domain);
        }
      });
      const rules_direct = [...rules_direct_set, ...rules_other_set].sort();
      function checkMatch(target) {
        const str = String(target).toLowerCase();
        for (const keyword of rules_re_keyword_set) {
          const key = String(keyword).toLowerCase();
          if (str.includes(key)) {
            notif_text_b.push(isdp + ": " + `${key} -> ${str}`);
            return true;
          }
        }
        return false;
      }

      return {
        rules: rules_direct.join("\n"),
        count: rules_direct.length,
      };
    }

    async function CidrRules(ipList) {
      if (!ipList || ipList.length === 0) return [];
      const cidrRuleSet = new Set();
      let cidrSet = new Set();
      for (const ip of ipList) {
        let matched = false;
        if (cidrSet.size > 0)
          checkCacheCidrs = [...new Set([...checkCacheCidrs, ...cidrSet])];
        if (checkCacheCidrs.length > 0) {
          for (const _cidr of checkCacheCidrs) {
            if (ipInCidr(ip, _cidr)) {
              _cidr_cache++;
              cidrRuleSet.add("IP-CIDR," + _cidr);
              matched = true;
              break;
            }
          }
        }
        if (!matched) {
          console.log("查询请求: " + ip);
          const cidr = await WhoisCidr(ip);
          if (cidr.length > 0) {
            _cidr_get++;
            console.log("收到: " + _cidr_get + ": " + cidr.join("  "));
            for (const i of cidr) {
              cidrRuleSet.add("IP-CIDR," + i);
              // 保存结果防止多次查询
              SaveCache(i);
            }
            cidrSet = new Set([...cidrSet, ...cidr]);
          } else {
            console.log("查询结果为空：" + ip);
          }
        }
      }
      _cidr_size += cidrRuleSet.size;
      if (_cidr_size > 0) {
        return [...cidrRuleSet];
      }
      return [];
    }
    function parseRulesAll(text) {
      const lines = text?.split("\n") || [];
      const excludeRules = [];
      const otherRules = [];
      let fileLength = 0;

      let inExcludeSection = false;
      let passedUpdate = false;

      for (let line of lines) {
        const trimmed = line.trim();

        if (trimmed.startsWith("# 手动规则")) {
          inExcludeSection = true;
          continue;
        }

        if (trimmed.startsWith("# 规则数量")) {
          fileLength = trimmed.match(/\d+/)?.[0] || 0;
          inExcludeSection = false;
          passedUpdate = true;
          continue;
        }

        if (!trimmed || trimmed.startsWith("# 更新时间")) continue;

        if (inExcludeSection) {
          excludeRules.push(trimmed);
          const [type, ...domainParts] = trimmed.split(",");
          if (domainParts.length > 0) {
            const domain = domainParts.join(",").trim().replace(/\s+/g, "");
            if (type === "DOMAIN-KEYWORD") {
              rules_re_keyword_set.add(domain);
            } else if (type === "DOMAIN-SUFFIX") {
              rules_re_other_set.add(domain);
            }
          }
        } else if (passedUpdate) {
          otherRules.push(trimmed);
        }
      }

      return {
        excludeRules,
        otherRules,
        fileLength,
      };
    }
    // 保存 CIDR 到缓存，并清理过期的
    function SaveCache(cidr) {
      const now = Date.now();
      let checkCacheCidr;
      try {
        checkCacheCidr = JSON.parse($persistentStore.read(CACHE_KEY)) || [];
      } catch (error) {
        checkCacheCidr = [];
        console.log(CACHE_KEY + " err1" + error.message);
      }
      // 清除过期
      checkCacheCidr = checkCacheCidr.filter(
        (item) => now - item.time < CACHE_TTL
      );
      // 检查是否已存在
      const alreadyExists = checkCacheCidr.some((item) => item.cidr === cidr);
      if (!alreadyExists) {
        checkCacheCidr.push({ cidr, time: now });
        $persistentStore.write(JSON.stringify(checkCacheCidr), CACHE_KEY);
      }
    }

    function ReadValidCache() {
      const now = Date.now();
      let checkCacheCidr;
      try {
        checkCacheCidr = JSON.parse($persistentStore.read(CACHE_KEY)) || [];
      } catch (error) {
        checkCacheCidr = [];
        console.log(CACHE_KEY + " err2" + error.message);
      }
      // 过滤过期的
      checkCacheCidr = checkCacheCidr.filter(
        (item) => now - item.time < CACHE_TTL
      );
      // 更新缓存（清理掉过期项）
      $persistentStore.write(JSON.stringify(checkCacheCidr), CACHE_KEY);
      // 返回 CIDR 字符串数组
      return checkCacheCidr.map((item) => item.cidr);
    }

    function fetchWithTimeout(url) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error("请求超时"));
        }, 1300);
        $httpClient.get(url, (error, response, data) => {
          clearTimeout(timer);
          if (error) {
            reject(error);
          } else {
            resolve(data);
          }
        });
      });
    }

    async function fetchAndParse(url) {
      let lastError = null;
      for (let attempt = 1; attempt <= 2; attempt++) {
        // 最多重试次数 2
        try {
          const data = await fetchWithTimeout(url);
          return JSON.parse(data);
        } catch (err) {
          lastError = err;
          console.log(`第 ${attempt} 次失败：`, err.message);
          if (attempt < 2) {
            console.log("准备重试...\n");
            await new Promise((res) => setTimeout(res, 1300));
          }
        }
      }
      console.log("全部尝试失败，最后错误：" + lastError?.message || lastError);
      return [];
    }

    async function WhoisCidr(ip) {
      const datas = await fetchAndParse(
        `https://stat.ripe.net/data/prefix-overview/data.json?resource=${ip}`
      );
      let cidr = datas?.data?.resource ? datas.data.resource : "";
      const cidrArray = cidr.match(/\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}/g) || [];
      if (cidrArray) {
        return cidrArray;
      }
      const data = await fetchAndParse(
        `https://wq.apnic.net/query?searchtext=${ip}`
      );
      let cidrs;
      try {
        cidrs = Array.from(
          new Set(
            data
              .filter(
                (item) =>
                  item.objectType === "route" || item.objectType === "NetRange"
              )
              .map((item) => {
                const attr = item.attributes.find(
                  (a) => a.name === "route" || a.name === "CIDR"
                );
                return attr ? attr?.values[0] : null;
              })
              .filter(Boolean)
          )
        );
      } catch (error) {
        console.log("APIA err " + error.message);
        cidrs = [];
      }
      if (cidrs.length > 0) {
        console.log("备用 API A");
        return cidrs;
      } else {
        try {
          const inetnumObj = data.find(
            (item) =>
              (item.type === "object" &&
                item.attributes.some((attr) => attr.name === "inetnum")) ||
              attr.name === "NetRange"
          );
          if (inetnumObj) {
            const inetnumValue = inetnumObj.attributes.find(
              (attr) => attr.name === "inetnum" || attr.name === "NetRange"
            ).values[0];

            const [ipStart, ipEnd] = inetnumValue.split(" - ");
            const cidr = calculateCidr(ipStart, ipEnd);
            console.log("备用 API AB");
            return cidr;
          } else {
            return [];
          }
        } catch (error) {
          console.log("APIA err " + error.message);
          return [];
        }
      }
    }

    function ipInCidr(ip, cidr) {
      const [cidrIp, maskBits] = cidr.split("/");
      const mask = (~0 << (32 - maskBits)) >>> 0;
      const ipInt = ipToInt(ip);
      const cidrIpInt = ipToInt(cidrIp);
      return (ipInt & mask) === (cidrIpInt & mask);
    }

    function ipToInt(ip) {
      return ip
        .split(".")
        .reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
    }

    function intToIp(ipInt) {
      return [
        (ipInt >>> 24) & 0xff,
        (ipInt >>> 16) & 0xff,
        (ipInt >>> 8) & 0xff,
        ipInt & 0xff,
      ].join(".");
    }

    function calculateCidr(startIp, endIp) {
      let start = ipToInt(startIp);
      let end = ipToInt(endIp);
      let cidrs = [];
      while (start <= end) {
        let maxSize = 32 - Math.floor(Math.log2(start & -start));
        let maxDiff = 32 - Math.floor(Math.log2(end - start + 1));
        let mask = Math.max(maxSize, maxDiff);
        cidrs.push(`${intToIp(start)}/${mask}`);
        start += Math.pow(2, 32 - mask);
      }
      return cidrs;
    }
  } catch (error) {
    console.log(error.message);
  } finally {
    $done({
      response: response,
    });
  }
})();
