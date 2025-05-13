// 2025-05-14 01:52:36
(async () => {
  // prettier-ignore
  let body = { d: "", p: "" },response = { body: JSON.stringify(body) },rule_direct_cidr = [], rule_proxy_cidr = [], ARGV = {}, reqbody, notif = "";
  try {
    // prettier-ignore
    try { ARGV = JSON.parse($argument); } catch (error) { throw new Error("$argument 解析错误" + error.message);}
    // prettier-ignore
    let { CN = "CNN", FINAL = "FINAL", COUNT = 5, CNIP = 0, CNHOST = 1, FINALIP = 1,  FINALHOST = 1,} = ARGV
    // prettier-ignore
    try { reqbody = JSON.parse($request?.body); } catch (error) {throw new Error("$request.body 解析错误" + error.message);}
    // prettier-ignore
    var checkCacheCidrs = [], more_set = new Set([]), re_set = new Set([]), key_set = new Set([]), _cidr_cache = 0, _cidr_get = 0, _cidr_size = 0, nt_a = [], nt_b = [], nt_c = [], nt_d = [];
    // prettier-ignore
    const TLDSet = new Set(["cn", "us", "uk", "jp", "de", "fr", "au", "ca", "ru", "kr", "sg", "in", "tw", "hk","mo", "nl", "es", "ch", "se", "no", "fi", "dk", "be", "br", "mx", "ar", "za", "nz", "il",]);
    const isIPv4 = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s),
      isIPv6 = (s) => /^([0-9a-fA-F]{1,4}:){2,7}/.test(s),
      today = new Date().toLocaleString("zh-CN", { hour12: false }),
      lines = reqbody.input_csv ? reqbody.input_csv.trim()?.split("\n") : [],
      toBool = (v) => v === true || v == 1,
      proxyRegex = new RegExp(FINAL),
      directRegex = new RegExp(CN),
      DOBJ = { hosts: [], ips: [] },
      POBJ = { hosts: [], ips: [] },
      CACHE_KEY = "Rule-Cidr-Cache",
      CACHE_TTL = 90 * 24 * 60 * 60 * 1000,
      {
        excludeRules: f_d_o,
        otherRules: f_d,
        fileLength: f_d_l,
      } = parseRulesAll(reqbody.file_direcr),
      {
        excludeRules: f_p_o,
        otherRules: f_p,
        fileLength: f_p_l,
      } = parseRulesAll(reqbody.file_proxy);

    CNIP = toBool(CNIP);
    CNHOST = toBool(CNHOST);
    FINALIP = toBool(FINALIP);
    FINALHOST = toBool(FINALHOST);

    if (FINALIP || CNIP) checkCacheCidrs = ReadValidCache();

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
        if (isIPv4(H)) {
          if (FINALIP) POBJ.ips.push(H);
        } else if (FINALHOST && !isIPv6(H)) {
          POBJ.hosts.push(`DOMAIN-SUFFIX,${H}`);
        }
      } else if (directRegex.test(P)) {
        if (isIPv4(H)) {
          if (CNIP) DOBJ.ips.push(H);
        } else if (CNHOST && !isIPv6(H)) {
          DOBJ.hosts.push(`DOMAIN-SUFFIX,${H}`);
        }
      }
    }

    CNIP && (rule_direct_cidr = await CidrRules(DOBJ.ips));
    FINALIP && (rule_proxy_cidr = await CidrRules(POBJ.ips));

    let { rules: rules_direct, count: count_direct } = processRules(
      new Set([...f_d, ...rule_direct_cidr, ...DOBJ.hosts]),
      true
    );
    let { rules: rules_proxy, count: count_proxy } = processRules(
      new Set([...f_p, ...rule_proxy_cidr, ...POBJ.hosts])
    );

    console.log("INCSV: \t" + lines?.length);
    console.log("PROXY: \t" + f_p_l);
    console.log("DIRECT: \t" + f_d_l);

    // prettier-ignore
    rules_direct =`# 手动规则: 以下规则优先级最高 不参与规则数量统计\n${f_d_o.join("\n")}\n\n# 更新时间: ${today}\n# 规则数量：当前共 ${count_direct || 0} 条规则\n\n` + rules_direct;
    // prettier-ignore
    rules_proxy =`# 手动规则: 以下规则优先级最高 不参与规则数量统计\n${f_p_o.join("\n")}\n\n# 更新时间: ${today}\n# 规则数量：当前共 ${count_proxy || 0} 条规则\n\n` + rules_proxy;

    // prettier-ignore
    const nt_x = count_direct != f_d_l ? `${f_d_l} -> ${count_direct}` : `${count_direct}`, nt_p = f_p_l != count_proxy ? `${f_p_l} -> ${count_proxy}` : `${count_proxy}`;

    nt_x != "0" && (notif += `${CN}: ${nt_x}  `);
    nt_p != "0" && (notif += `${FINAL}: ${nt_p}  `);

    // prettier-ignore
    _cidr_get > 0 &&(notif += `\nIP-CIDR: 请求查询:${_cidr_get}, 缓存${_cidr_cache}, 最终规则:${_cidr_size}`);
    // prettier-ignore
    let t = nt_a.length > 0 ? `\n\n去掉 [${CN}] 里有的规则:\n${nt_a.join("\n")}\n` : "";
    // prettier-ignore
    t += nt_b.length > 0? `\n\n去掉命中 KEYWORD 的规则: \n${nt_b.join("\n")}\n`: "";
    // prettier-ignore
    t += nt_c.length > 0 ? `\n\n去掉命中 国家顶级域名 的多余规则: \n${nt_c.join("\n")}\n` : "";
    // prettier-ignore
    t += nt_d.length > 0 ? `\n\n去掉命中 手动规则 的规则: \n${nt_d.join("\n")}\n` : "";

    $notification.post("FindRule", "", notif);
    console.log(t + "\n\n" + notif + "\n");

    function processRules(ruleSet, is_cn = false) {
      let isdp = is_cn ? CN : FINAL;
      const other_set = new Set([]);
      const ipcidr_set = new Set([]);
      const direct_set = new Set([]);

      let rule_split = [];
      for (const item of ruleSet) {
        const [type, ...domainParts] = item.split(",");
        if (domainParts.length === 0) continue;
        const domain = domainParts.join(",").trim().replace(/\s+/g, "");
        rule_split.push([type, domain]);
        if (type === "DOMAIN-KEYWORD") key_set.add(domain);
      }
      rule_split.forEach((i) => {
        const type = i[0];
        const domain = i[1];
        if (type === "DOMAIN-SUFFIX") {
          const parts = domain.split(".");
          const part_len = parts.length;
          if (more_set.has(domain)) {
            nt_d.push(isdp + ": " + domain);
            return;
          }
          if (!is_cn) {
            if (re_set.has(domain)) {
              nt_a.push(isdp + ": " + domain);
              return;
            }
          } else re_set.add(domain);
          if (part_len > 0) {
            const tld = parts[part_len - 1];
            if (TLDSet.has(tld)) {
              part_one(part_len, is_cn, tld, domain);
            } else part_other(parts, part_len, domain, is_cn);
          }
        } else is_cidr(type, domain);
      });

      function part_other(parts, part_len, domain, is_cn) {
        if (!checkMatch(domain)) {
          if (part_len > 2) {
            let mat = false;
            const doma = parts.slice(-2).join(".");
            if (is_cn) {
              re_set.add(doma);
              mat = true;
            } else if (!re_set.has(doma)) mat = true;
            mat && add_d_s(doma);
          } else add_d_s(domain);
        }
      }

      function part_one(part_len, is_cn, tld, domain) {
        if (part_len == 0) return;
        if (is_cn) {
          re_set.add(tld);
          add_d_s(tld);
          nt_c.push(`${isdp}: ${tld} -> ${domain}`);
        } else if (re_set.has(tld)) {
          nt_a.push(`${isdp}: ${domain}`);
          return;
        } else {
          nt_c.push(`${isdp}: ${tld} -> ${domain}`);
          add_d_s(tld);
        }
      }

      function checkMatch(target) {
        const str = String(target).toLowerCase();
        for (const keyword of key_set) {
          const key = String(keyword).toLowerCase();
          if (str.includes(key)) {
            nt_b.push(`${isdp}: ${key} -> ${str}`);
            return true;
          }
        }
        return false;
      }

      function is_cidr(type, domain) {
        if (type === "IP-CIDR") {
          if (!checkMatch(domain)) {
            ipcidr_set.add(type + "," + domain);
          }
        } else other_set.add(type + "," + domain);
      }

      function add_d_s(i) {
        direct_set.add("DOMAIN-SUFFIX," + i);
      }

      const rules_direct = [
        ...direct_set,
        ...other_set,
        ...dedupeCIDRs([...ipcidr_set]),
      ].sort();

      return {
        rules: rules_direct.join("\n"),
        count: rules_direct.length,
      };
    }

    async function CidrRules(ipList) {
      if (!ipList || ipList.length === 0) return [];
      const cidrRuleSet = new Set([]);
      let cidrSet = new Set([]);
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
              SaveCache(i); // 保存结果防止多次查询
            }
            cidrSet = new Set([...cidrSet, ...cidr]);
          } else console.log("查询结果为空：" + ip);
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
              key_set.add(domain);
            } else if (type === "DOMAIN-SUFFIX") more_set.add(domain);
          }
        } else if (passedUpdate) otherRules.push(trimmed);
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
          } else resolve(data);
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
      if (cidrArray) return cidrArray;

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
          } else return [];
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

    function parseCIDR(cidrStr) {
      const match = cidrStr.match(/IP-CIDR,([0-9.]+)\/(\d+)/);
      if (!match) return null;
      const [_, ip, prefixLength] = match;
      const ipInt = ipToInt(ip);
      const prefix = parseInt(prefixLength);
      const mask = ~(2 ** (32 - prefix) - 1) >>> 0;
      const start = ipInt & mask;
      const end = start + 2 ** (32 - prefix) - 1;
      return { raw: cidrStr, start, end, prefix };
    }

    function isSubset(a, b) {
      return a.start >= b.start && a.end <= b.end;
    }

    function dedupeCIDRs(rawList) {
      const cidrs = rawList.map(parseCIDR).filter(Boolean);
      const excluded = new Set([]);
      for (let i = 0; i < cidrs.length; i++) {
        for (let j = 0; j < cidrs.length; j++) {
          if (i !== j && isSubset(cidrs[i], cidrs[j])) {
            excluded.add(cidrs[i].raw);
            break;
          }
        }
      }

      const result = rawList.filter((item) => !excluded.has(item));
      excluded.size > 0 &&
        console.log("\n去除的 CIDR: \n" + [...excluded].join("\n") + "\n");
      return result;
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
    // console.log("\nrules_direct\n");
    // console.log(rules_direct);
    // console.log("\nrules_proxy\n");
    // console.log(rules_proxy);
    response.body = JSON.stringify({ d: rules_direct, p: rules_proxy });
  } catch (error) {
    console.log(error.message);
  } finally {
    $done({
      response: response,
    });
  }
})();