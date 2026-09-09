/**
 * Notes enrolment gate — preview/staging only (lives on the `notes-gate` branch;
 * `main` and therefore production never carries this file).
 *
 * Contract (see coding_plans/notes-content-protection.md, step 2 A5):
 *  1. Verify the `te_notes` cookie HMAC in constant time, then check `exp`.
 *  2. On success call next() and re-apply step 1's headers on the response,
 *     because Pages Functions disable the `_headers` file for the whole project.
 *  3. On failure return 403 with a human-readable page, same headers applied.
 *  4. Skip the check for /robots.txt only. Assets are gated too.
 *
 * Step 1's four protections, re-applied here in code:
 *  - X-Robots-Tag: noindex, nofollow
 *  - Content-Security-Policy: frame-ancestors https://*.techexplorations.com https://techexplorations.com
 *  - Referrer-Policy: no-referrer
 *  - deletion of Access-Control-Allow-Origin (must stay absent, even with an
 *    explicit Origin header on the request)
 */

const COOKIE_NAME = "te_notes";
const SKIP_PATHS = new Set(["/robots.txt"]);

const STEP1_HEADERS = {
  "X-Robots-Tag": "noindex, nofollow",
  "Content-Security-Policy":
    "frame-ancestors https://*.techexplorations.com https://techexplorations.com",
  "Referrer-Policy": "no-referrer",
};

function base64UrlToBytes(value) {
  const b64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Constant-time comparison; length mismatch returns false without leaking order. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Returns the decoded payload object, or null when the cookie is invalid/expired. */
async function verifyCookie(cookieValue, secret) {
  const dot = cookieValue.indexOf(".");
  if (dot <= 0 || dot === cookieValue.length - 1) return null;
  const payloadB64 = cookieValue.slice(0, dot);
  const signatureB64 = cookieValue.slice(dot + 1);

  let provided;
  try {
    provided = base64UrlToBytes(signatureB64);
  } catch {
    return null;
  }

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  // Signs the transmitted base64url payload string — byte-identical to what the
  // WordPress mu-plugin hashes, so no re-encoding rules can drift apart.
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(payloadB64))
  );
  if (!timingSafeEqual(expected, provided)) return null;

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
  } catch {
    return null;
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    typeof payload.exp !== "number" ||
    payload.exp <= Math.floor(Date.now() / 1000)
  ) {
    return null;
  }
  return payload;
}

function applyStep1Headers(headers) {
  for (const [name, value] of Object.entries(STEP1_HEADERS)) {
    headers.set(name, value);
  }
  headers.delete("Access-Control-Allow-Origin");
}

function gateResponse() {
  const body = [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Chapter locked</title></head>",
    '<body style="font-family:system-ui,sans-serif;padding:3rem;line-height:1.6;max-width:40rem;margin:auto">',
    "<h1>This chapter is part of the course</h1>",
    "<p>Open this chapter from your course at app.techexplorations.com</p>",
    "</body></html>",
  ].join("");
  const response = new Response(body, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
  applyStep1Headers(response.headers);
  return response;
}

function readCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);

  if (SKIP_PATHS.has(url.pathname)) {
    return next();
  }

  const secret = env.TE_NOTES_SECRET;
  const cookieValue = readCookie(request.headers.get("Cookie"), COOKIE_NAME);

  // Missing secret (misconfigured deployment) fails closed: everything 403s
  // rather than silently serving the book unauthenticated.
  const payload =
    secret && cookieValue ? await verifyCookie(cookieValue, secret) : null;

  if (!payload) {
    return gateResponse();
  }

  const response = await next();
  applyStep1Headers(response.headers);
  return response;
}
