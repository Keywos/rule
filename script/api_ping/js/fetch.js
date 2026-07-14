// fetch.js 1.0.1

const DEFAULT_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) " +
    "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0",
  Accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Dest": "document",
};

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods":
    "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
  "Access-Control-Max-Age": "86400",
  linkey: "key",
};

const MAX_REDIRECTS = 9;

let finished = false;
let requestHeaders = null;
let requestBody = null;

/**
 * 创建 CORS 响应头。
 */
function createCorsHeaders(origin) {
  if (!origin || origin === "*") {
    return {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods":
        CORS_HEADERS["Access-Control-Allow-Methods"],
      "Access-Control-Allow-Headers":
        CORS_HEADERS["Access-Control-Allow-Headers"],
      "Access-Control-Expose-Headers":
        CORS_HEADERS["Access-Control-Expose-Headers"],
      "Access-Control-Max-Age":
        CORS_HEADERS["Access-Control-Max-Age"],
      linkey: CORS_HEADERS.linkey,
    };
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods":
      CORS_HEADERS["Access-Control-Allow-Methods"],
    "Access-Control-Allow-Headers":
      CORS_HEADERS["Access-Control-Allow-Headers"],
    "Access-Control-Expose-Headers":
      CORS_HEADERS["Access-Control-Expose-Headers"],
    "Access-Control-Max-Age":
      CORS_HEADERS["Access-Control-Max-Age"],
    linkey: CORS_HEADERS.linkey,
  };
}

/**
 * 清理不能直接透传的响应头，并添加 CORS。
 */
function cleanResponseHeaders(headers, origin) {
  const result = {};

  if (headers && typeof headers === "object") {
    try {
      for (const key in headers) {
        if (
          !Object.prototype.hasOwnProperty.call(headers, key)
        ) {
          continue;
        }

        const lower = String(key).toLowerCase();

        if (
          lower === "content-length" ||
          lower === "content-encoding" ||
          lower === "transfer-encoding" ||
          lower === "connection" ||
          lower === "keep-alive" ||
          lower === "proxy-authenticate" ||
          lower === "proxy-authorization" ||
          lower === "te" ||
          lower === "trailer" ||
          lower === "upgrade" ||
          lower.indexOf("access-control-") === 0
        ) {
          continue;
        }

        result[key] = headers[key];
      }
    } catch (e) {
      console.log("cleanResponseHeaders: " + e);
    }
  }

  result["Access-Control-Allow-Origin"] =
    origin || "*";
  result["Access-Control-Allow-Methods"] =
    CORS_HEADERS["Access-Control-Allow-Methods"];
  result["Access-Control-Allow-Headers"] =
    CORS_HEADERS["Access-Control-Allow-Headers"];
  result["Access-Control-Expose-Headers"] =
    CORS_HEADERS["Access-Control-Expose-Headers"];
  result["Access-Control-Max-Age"] =
    CORS_HEADERS["Access-Control-Max-Age"];
  result.linkey = CORS_HEADERS.linkey;

  return result;
}

/**
 * 读取查询参数。
 */
function getQueryParam(name) {
  try {
    if (
      typeof $request === "undefined" ||
      !$request ||
      !$request.url
    ) {
      return null;
    }

    const url = String($request.url);
    const queryIndex = url.indexOf("?");

    if (queryIndex < 0) {
      return null;
    }

    const query = url.substring(queryIndex + 1);
    const parts = query.split("&");
    const prefix = name + "=";

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      if (part.indexOf(prefix) === 0) {
        const value = part.substring(prefix.length);

        try {
          return decodeURIComponent(
            value.replace(/\+/g, " ")
          );
        } catch (decodeError) {
          console.log(
            "decodeURIComponent: " +
            decodeError
          );

          return value;
        }
      }

      if (part === name) {
        return "";
      }
    }

    return null;
  } catch (e) {
    console.log("getQueryParam: " + e);
    return null;
  }
}

/**
 * 安全解析 JSON。
 */
function parseJSON(value) {
  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch (e) {
    console.log("JSON Parse Error: " + e);
    return null;
  }
}

/**
 * 只允许执行一次 $done。
 */
function finish(status, headers, body) {
  if (finished) {
    return;
  }

  finished = true;

  let outputBody = "";

  if (body != null) {
    outputBody =
      typeof body === "string"
        ? body
        : String(body);
  }

  try {
    $done({
      response: {
        status: status,
        headers: headers || createCorsHeaders("*"),
        body: outputBody,
      },
    });
  } catch (e) {
    console.log("finish: " + e);

    try {
      $done();
    } catch (doneError) {
      console.log("$done Error: " + doneError);
    }
  }
}

/**
 * 判断是否为重定向状态码。
 */
function isRedirectStatus(status) {
  return (
    status === 301 ||
    status === 302 ||
    status === 303 ||
    status === 307 ||
    status === 308
  );
}

/**
 * 不区分大小写获取响应头。
 */
function getHeader(headers, targetName) {
  if (!headers) {
    return null;
  }

  if (headers[targetName] != null) {
    return headers[targetName];
  }

  const lowerTarget = targetName.toLowerCase();

  for (const key in headers) {
    if (
      Object.prototype.hasOwnProperty.call(headers, key) &&
      String(key).toLowerCase() === lowerTarget
    ) {
      return headers[key];
    }
  }

  return null;
}

/**
 * 解析重定向地址。
 */
function resolveRedirect(location, base) {
  location = String(location);

  if (/^https?:\/\//i.test(location)) {
    return location;
  }

  if (typeof URL === "function") {
    try {
      return new URL(location, base).href;
    } catch (e) {
      console.log("URL resolve: " + e);
    }
  }

  const originMatch = String(base).match(
    /^(https?:\/\/[^/]+)/i
  );

  if (!originMatch) {
    return location;
  }

  const origin = originMatch[1];

  if (location.indexOf("//") === 0) {
    const protocolMatch = String(base).match(
      /^(https?):/i
    );

    return (
      (protocolMatch
        ? protocolMatch[1]
        : "https") +
      ":" +
      location
    );
  }

  if (location.charAt(0) === "/") {
    return origin + location;
  }

  if (location.charAt(0) === "?") {
    const cleanBase = String(base).split("#")[0];
    const queryIndex = cleanBase.indexOf("?");

    return (
      (queryIndex >= 0
        ? cleanBase.substring(0, queryIndex)
        : cleanBase) + location
    );
  }

  if (location.charAt(0) === "#") {
    return String(base).split("#")[0] + location;
  }

  const cleanBase = String(base)
    .split("#")[0]
    .split("?")[0];

  const lastSlash = cleanBase.lastIndexOf("/");
  const directory =
    lastSlash >= 0
      ? cleanBase.substring(0, lastSlash + 1)
      : cleanBase + "/";

  return directory + location;
}

/**
 * 合并默认请求头和用户请求头。
 * 此函数只在脚本启动时执行一次。
 */
function buildRequestHeaders(extraHeaders) {
  const result = {};
  let key;

  for (key in DEFAULT_HEADERS) {
    if (
      Object.prototype.hasOwnProperty.call(
        DEFAULT_HEADERS,
        key
      )
    ) {
      result[key] = DEFAULT_HEADERS[key];
    }
  }

  if (
    !extraHeaders ||
    typeof extraHeaders !== "object"
  ) {
    return result;
  }

  for (key in extraHeaders) {
    if (
      !Object.prototype.hasOwnProperty.call(
        extraHeaders,
        key
      )
    ) {
      continue;
    }

    const lower = String(key).toLowerCase();

    /*
     * 这些请求头应交给 HTTP 客户端自动管理。
     */
    if (
      lower === "host" ||
      lower === "content-length" ||
      lower === "transfer-encoding" ||
      lower === "connection"
    ) {
      continue;
    }

    /*
     * 避免同时出现 User-Agent 和 user-agent。
     */
    if (lower === "user-agent") {
      result["User-Agent"] = extraHeaders[key];
      continue;
    }

    /*
     * 避免同时出现 Accept 和 accept。
     */
    if (lower === "accept") {
      result.Accept = extraHeaders[key];
      continue;
    }

    result[key] = extraHeaders[key];
  }

  return result;
}

/**
 * 处理 HTTP 响应。
 */
function handleResponse(
  url,
  redirectCount,
  method,
  err,
  resp,
  body
) {
  try {
    if (err) {
      console.log("HTTP Error: " + err);

      finish(
        502,
        createCorsHeaders("*"),
        String(err)
      );

      return;
    }

    if (!resp) {
      finish(
        502,
        createCorsHeaders("*"),
        "No response"
      );

      return;
    }

    let status =
      resp.statusCode != null
        ? Number(resp.statusCode)
        : Number(resp.status);

    if (!status || status < 100) {
      status = 200;
    }

    const responseHeaders =
      resp.headers &&
      typeof resp.headers === "object"
        ? resp.headers
        : {};

    console.log("Status: " + status);

    if (isRedirectStatus(status)) {
      const location = getHeader(
        responseHeaders,
        "location"
      );

      if (location) {
        const nextURL = resolveRedirect(
          location,
          url
        );

        console.log("Redirect: " + nextURL);

        /*
         * HTTP 303 必须切换为 GET。
         * 301/302 对 POST 通常也按照浏览器行为切换为 GET。
         * 307/308 保留原方法和请求体。
         */
        let nextMethod = method;

        if (
          status === 303 ||
          ((status === 301 || status === 302) &&
            method === "POST")
        ) {
          nextMethod = "GET";
        }

        sendRequest(
          nextURL,
          redirectCount + 1,
          nextMethod
        );

        return;
      }
    }

    finish(
      status,
      cleanResponseHeaders(
        responseHeaders,
        "*"
      ),
      body
    );
  } catch (e) {
    console.log("Callback Exception: " + e);

    if (e && e.stack) {
      console.log(e.stack);
    }

    finish(
      500,
      createCorsHeaders("*"),
      (e && e.stack) || String(e)
    );
  }
}

/**
 * 发起请求。
 */
function sendRequest(url, redirectCount, method) {
  if (finished) {
    return;
  }

  if (redirectCount >= MAX_REDIRECTS) {
    finish(
      508,
      createCorsHeaders("*"),
      "Too many redirects"
    );

    return;
  }

  if (
    typeof $httpClient === "undefined" ||
    !$httpClient
  ) {
    finish(
      500,
      createCorsHeaders("*"),
      "$httpClient unavailable"
    );

    return;
  }

  const options = {
    url: url,
    headers: requestHeaders,
  };

  if (method === "POST" && requestBody != null) {
    options.body = requestBody;
  }

  console.log("Request: " + method + " " + url);

  const callback = function (err, resp, body) {
    handleResponse(
      url,
      redirectCount,
      method,
      err,
      resp,
      body
    );
  };

  try {
    if (method === "POST") {
      if (typeof $httpClient.post !== "function") {
        finish(
          500,
          createCorsHeaders("*"),
          "$httpClient.post unavailable"
        );

        return;
      }

      $httpClient.post(options, callback);
      return;
    }

    if (typeof $httpClient.get !== "function") {
      finish(
        500,
        createCorsHeaders("*"),
        "$httpClient.get unavailable"
      );

      return;
    }

    $httpClient.get(options, callback);
  } catch (e) {
    console.log("HTTP Client Exception: " + e);

    if (e && e.stack) {
      console.log(e.stack);
    }

    finish(
      500,
      createCorsHeaders("*"),
      (e && e.stack) || String(e)
    );
  }
}

/**
 * 主程序。
 */
try {
  if (typeof $request === "undefined" || !$request) {
    finish(
      500,
      createCorsHeaders("*"),
      "$request unavailable"
    );
  } else {
    const incomingMethod = String(
      $request.method || "GET"
    ).toUpperCase();

    if (incomingMethod === "OPTIONS") {
      finish(
        204,
        createCorsHeaders("*"),
        ""
      );
    } else {
      const target = getQueryParam("url");

      if (!target) {
        finish(
          400,
          createCorsHeaders("*"),
          "missing url parameter"
        );
      } else {
        const extraHeaders =
          parseJSON(
            getQueryParam("linkeyheaders")
          ) || {};

        requestHeaders =
          buildRequestHeaders(extraHeaders);

        requestBody =
          getQueryParam("linkeybody");

        sendRequest(
          target,
          0,
          requestBody != null ? "POST" : "GET"
        );
      }
    }
  }
} catch (e) {
  console.log("Fatal: " + e);

  if (e && e.stack) {
    console.log(e.stack);
  }

  finish(
    500,
    createCorsHeaders("*"),
    (e && e.stack) || String(e)
  );
}