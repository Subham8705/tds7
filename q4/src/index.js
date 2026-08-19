const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const ALLOWED_HOSTS = ["cdn-784jyvn.example", "app-feo6cve.example"];

function decodePayload(str) {
  let decoded = str;

  // 1. percent-escapes
  try {
    decoded = decodeURIComponent(decoded);
  } catch(e) {
    decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (m, p1) => String.fromCharCode(parseInt(p1, 16)));
  }

  // 2. HTML entities
  decoded = decoded.replace(/&#(\d+);/g, (m, p1) => String.fromCharCode(parseInt(p1, 10)));
  decoded = decoded.replace(/&#x([0-9A-Fa-f]+);/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16)));
  
  const named = { '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'", '&amp;': '&' };
  decoded = decoded.replace(/&(lt|gt|quot|apos|amp);/g, m => named[m]);

  // 3. \uXXXX escapes
  decoded = decoded.replace(/\\u([0-9A-Fa-f]{4})/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16)));

  return decoded;
}

function extractUrls(text, channel) {
  const urls = [];
  if (channel === "html") {
    const regex = /\b(?:src|href)\s*=\s*(["'])(.*?)\1/gi;
    let match;
    while ((match = regex.exec(text)) !== null) {
      urls.push(match[2]);
    }
  } else if (channel === "markdown") {
    const regex = /\]\(([^)]+)\)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      urls.push(match[1].trim());
    }
  } else if (channel === "url") {
    urls.push(text.trim());
  }
  return urls;
}

function getScheme(urlStr) {
  const match = urlStr.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (match) {
    return match[1].toLowerCase() + ":";
  }
  return null;
}

function hasScriptTag(text) {
  return /<\s*(script|iframe|object|embed)\b/i.test(text);
}

function hasEventHandler(text) {
  return /\bon[a-z]+\s*=/i.test(text);
}

function hasDangerousScheme(text, channel) {
  if (/(javascript|data|vbscript)\s*:/i.test(text)) {
    return true;
  }
  const urls = extractUrls(text, channel);
  for (const u of urls) {
    const scheme = getScheme(u);
    if (scheme !== null && scheme !== "http:" && scheme !== "https:") {
      return true;
    }
  }
  return false;
}

function hasExternalExfil(text, channel) {
  const urls = extractUrls(text, channel);
  for (let u of urls) {
    if (u.startsWith("//")) {
      u = "https:" + u;
    }
    try {
      const parsed = new URL(u);
      if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
        return true;
      }
    } catch(e) {
      // Relative URL, ignore
    }
  }
  return false;
}

function hasSqlMetachar(text) {
  return /['";]|--|\/\*|\bunion\b|or 1=1/i.test(text);
}

function hasShellMetachar(text) {
  return /[;&|`<>]|\$\(|\$\{/.test(text);
}

function checkChannelRules(channel, text) {
  if (channel === "html") {
    if (hasScriptTag(text)) return "SCRIPT_TAG";
    if (hasEventHandler(text)) return "EVENT_HANDLER";
    if (hasDangerousScheme(text, channel)) return "DANGEROUS_SCHEME";
    if (hasExternalExfil(text, channel)) return "EXTERNAL_EXFIL";
  } else if (channel === "markdown") {
    if (hasDangerousScheme(text, channel)) return "DANGEROUS_SCHEME";
    if (hasExternalExfil(text, channel)) return "EXTERNAL_EXFIL";
  } else if (channel === "url") {
    if (hasDangerousScheme(text, channel)) return "DANGEROUS_SCHEME";
    if (hasExternalExfil(text, channel)) return "EXTERNAL_EXFIL";
  } else if (channel === "sql") {
    if (hasSqlMetachar(text)) return "SQL_METACHAR";
  } else if (channel === "shell") {
    if (hasShellMetachar(text)) return "SHELL_METACHAR";
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS, status: 204 });
    }

    if (request.method === "GET") {
      return Response.json(
        { service: "TDS GA7 Sanitize Output", status: "ok" },
        { headers: CORS_HEADERS }
      );
    }

    if (request.method === "POST" && new URL(request.url).pathname === "/sanitize-output") {
      try {
        const body = await request.json();

        // 1. INVALID_SCHEMA
        const validChannels = ["html", "markdown", "url", "sql", "shell"];
        if (
          typeof body !== "object" ||
          body === null ||
          !validChannels.includes(body.channel) ||
          typeof body.output !== "string" ||
          body.output.length > 20000
        ) {
          return Response.json({ safe: false, reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
        }

        const channel = body.channel;
        const output = body.output;

        // 2. ENCODED_PAYLOAD
        const decoded = decodePayload(output);
        if (decoded !== output) {
          const decodedReason = checkChannelRules(channel, decoded);
          if (decodedReason !== null) {
            return Response.json({ safe: false, reason: "ENCODED_PAYLOAD" }, { headers: CORS_HEADERS });
          }
        }

        // 3. Channel rules on original output
        const reason = checkChannelRules(channel, output);
        if (reason !== null) {
          return Response.json({ safe: false, reason: reason }, { headers: CORS_HEADERS });
        }

        return Response.json({ safe: true, reason: "SAFE" }, { headers: CORS_HEADERS });

      } catch (err) {
        return Response.json({ safe: false, reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS, status: 400 });
      }
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};
