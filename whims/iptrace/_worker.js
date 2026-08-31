// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 honeok <i@honeok.com>

const EMOJI_BASE = 127397;
const ISO_REGEX = /^[A-Z]{2}$/;
// 仅缓存时区格式化器, 偏移量仍实时计算避免夏令时切换后使用旧值
const TZ_FORMATTERS = new Map();
// 预构建常用响应头, 避免在请求热路径中重复创建和合并
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const TEXT_HEADERS = {
  ...CORS_HEADERS,
  "Content-Type": "text/plain; charset=utf-8",
};
const JSON_HEADERS = {
  ...CORS_HEADERS,
  "Content-Type": "application/json; charset=utf-8",
};
const METHOD_NOT_ALLOWED_HEADERS = {
  ...TEXT_HEADERS,
  Allow: "GET, HEAD, OPTIONS",
};

// 复用预构建响应头, 并确保 HEAD 请求不返回正文
function createResponse(request, body, headers, status = 200) {
  return new Response(request.method === "HEAD" ? null : body, {
    status,
    headers,
  });
}

// 国旗转换
function getFlag(countryCode) {
  if (!countryCode || !ISO_REGEX.test(countryCode)) return undefined;
  return String.fromCodePoint(EMOJI_BASE + countryCode.charCodeAt(0), EMOJI_BASE + countryCode.charCodeAt(1));
}

// 获取 Flag 的 Unicode 字符串
function getFlagUnicode(countryCode) {
  if (!countryCode || !ISO_REGEX.test(countryCode)) return undefined;
  const hex1 = (EMOJI_BASE + countryCode.charCodeAt(0)).toString(16).toUpperCase();
  const hex2 = (EMOJI_BASE + countryCode.charCodeAt(1)).toString(16).toUpperCase();
  return `U+${hex1} U+${hex2}`;
}

// 获取 WARP 状态
function getWarp(asn) {
  if (!asn) return "off";
  const numericAsn = Number(asn);
  return numericAsn === 13335 || numericAsn === 209242 ? "on" : "off";
}

// 获取时区偏移量
function getOffset(tz) {
  if (!tz) return undefined;
  try {
    let formatter = TZ_FORMATTERS.get(tz);
    if (!formatter) {
      formatter = new Intl.DateTimeFormat("en-US", {
        timeZone: tz,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23",
      });
      if (TZ_FORMATTERS.size < 500) TZ_FORMATTERS.set(tz, formatter);
    }

    const now = new Date();
    now.setMilliseconds(0);
    let year;
    let month;
    let day;
    let hour;
    let minute;
    let second;
    for (const { type, value } of formatter.formatToParts(now)) {
      switch (type) {
        case "year":
          year = Number(value);
          break;
        case "month":
          month = Number(value);
          break;
        case "day":
          day = Number(value);
          break;
        case "hour":
          hour = Number(value);
          break;
        case "minute":
          minute = Number(value);
          break;
        case "second":
          second = Number(value);
          break;
        default:
          break;
      }
    }
    // 将目标时区的本地时间视为 UTC, 与当前时间比较得到偏移秒数
    const localTimeAsUtc = Date.UTC(year, month - 1, day, hour, minute, second);
    return Math.round((localTimeAsUtc - now.getTime()) / 1000);
  } catch (error) {
    return undefined;
  }
}

export default {
  fetch(request) {
    // 浏览器跨域预检不进入业务路由
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    // IP 查询接口仅接受只读方法, 其他方法明确返回 405
    if (request.method !== "GET" && request.method !== "HEAD") {
      return createResponse(request, "Method Not Allowed", METHOD_NOT_ALLOWED_HEADERS, 405);
    }

    const reqPath = new URL(request.url).pathname;

    // 处理图标请求
    if (reqPath === "/favicon.ico") {
      const userAgent = request.headers.get("User-Agent");
      if (userAgent) {
        return Response.redirect(
          "https://fastly.jsdelivr.net/gh/devicons/devicon@latest/icons/linux/linux-original.svg",
          301,
        );
      }
      return new Response(null, { status: 204 });
    }

    // 提取通用变量
    const clientIP = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const cfData = request.cf || {};

    // 根路径仅返回 IP
    if (reqPath === "/") {
      return createResponse(request, clientIP + "\n", TEXT_HEADERS);
    }

    // JSON 返回详细信息
    if (reqPath === "/json") {
      const resData = {
        ip: clientIP,
        asn: cfData.asn,
        org: cfData.asOrganization,
        continent: cfData.continent,
        country: cfData.country,
        region: cfData.region,
        regionCode: cfData.regionCode,
        city: cfData.city,
        emoji: getFlag(cfData.country),
        emoji_unicode: getFlagUnicode(cfData.country),
        postalCode: cfData.postalCode,
        metroCode: cfData.metroCode,
        latitude: cfData.latitude,
        longitude: cfData.longitude,
        offset: getOffset(cfData.timezone),
        timezone: cfData.timezone,
        colo: cfData.colo,
        warp: getWarp(cfData.asn),
      };

      const resJson = JSON.stringify(resData, null, 2);
      return createResponse(request, resJson, JSON_HEADERS);
    }

    // 避免异常路径穿透
    return createResponse(request, "Not Found", TEXT_HEADERS, 404);
  },
};
